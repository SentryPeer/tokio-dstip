// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Gavin Henry <ghenry@sentrypeer.org>

use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "linux")]
fn enable_pktinfo(fd: i32, ipv6: bool) {
    use nix::libc::{IP_PKTINFO, IPV6_RECVPKTINFO, SOL_IP, SOL_IPV6};
    unsafe {
        let optval: libc::c_int = 1;
        if ipv6 {
            libc::setsockopt(
                fd,
                SOL_IPV6,
                IPV6_RECVPKTINFO,
                &optval as *const _ as *const _,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        } else {
            libc::setsockopt(
                fd,
                SOL_IP,
                IP_PKTINFO,
                &optval as *const _ as *const _,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn enable_pktinfo(fd: i32, ipv6: bool) {
    use nix::libc::{IP_RECVDSTADDR, IPV6_RECVPKTINFO, SOL_IP, SOL_IPV6};
    unsafe {
        let optval: libc::c_int = 1;
        if ipv6 {
            libc::setsockopt(
                fd,
                SOL_IPV6,
                IPV6_RECVPKTINFO,
                &optval as *const _ as *const _,
                4,
            );
        } else {
            libc::setsockopt(
                fd,
                SOL_IP,
                IP_RECVDSTADDR,
                &optval as *const _ as *const _,
                4,
            );
        }
    }
}

/// Async UDP socket with destination IP support
pub struct UdpSocketWithDst {
    async_fd: AsyncFd<Socket>,
}

impl UdpSocketWithDst {
    /// Bind to a socket address and return a UDP receiver
    pub fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;

        enable_pktinfo(socket.as_raw_fd(), matches!(addr, SocketAddr::V6(_)));

        socket.set_nonblocking(true)?;
        let async_fd = AsyncFd::new(socket)?;
        Ok(Self { async_fd })
    }

    /// Receive a UDP packet, returning (data, source addr, destination IP)
    pub async fn recv_from(&self) -> std::io::Result<(Vec<u8>, SocketAddr, std::net::IpAddr)> {
        let mut buf = [0u8; 1500];

        // Allocate buffer for control message
        let mut cmsg_buf = vec![0u8; 256];

        loop {
            let guard = self.async_fd.readable().await?;
            let raw_fd = guard.get_ref().as_raw_fd();

            // Prepare msghdr for recvmsg
            let mut iovec = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };

            let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let src_addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

            let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
            msghdr.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
            msghdr.msg_namelen = src_addr_len;
            msghdr.msg_iov = &mut iovec;
            msghdr.msg_iovlen = 1;
            msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msghdr.msg_controllen = cmsg_buf.len() as _;

            let received = unsafe { libc::recvmsg(raw_fd, &mut msghdr, 0) };

            if received < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(err);
            }

            // Extract source address
            let src_addr = unsafe { socket2::SockAddr::new(src_addr, src_addr_len) };
            let src = src_addr.as_socket().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Invalid source address")
            })?;

            // Extract destination IP
            let dst_ip = extract_dst_ip_from_msghdr(&msghdr)
                .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED));

            // Extract data
            let data = buf[..received as usize].to_vec();

            return Ok((data, src, dst_ip));
        }
    }
}

fn extract_dst_ip_from_msghdr(msghdr: &libc::msghdr) -> Option<std::net::IpAddr> {
    let mut cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(msghdr) };
    while !cmsg.is_null() {
        let cmsghdr = unsafe { &*cmsg };

        #[cfg(target_os = "linux")]
        {
            if cmsghdr.cmsg_level == libc::SOL_IP && cmsghdr.cmsg_type == libc::IP_PKTINFO {
                let pktinfo = unsafe { *(libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo) };
                return Some(std::net::IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    pktinfo.ipi_addr.s_addr,
                ))));
            } else if cmsghdr.cmsg_level == libc::SOL_IPV6
                && cmsghdr.cmsg_type == libc::IPV6_PKTINFO
            {
                let pktinfo = unsafe { *(libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo) };
                return Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    pktinfo.ipi6_addr.s6_addr,
                )));
            }
        }

        #[cfg(target_os = "macos")]
        {
            if cmsghdr.cmsg_level == libc::IPPROTO_IP && cmsghdr.cmsg_type == libc::IP_RECVDSTADDR {
                let addr_ptr = unsafe { libc::CMSG_DATA(cmsg) as *const u8 };
                let mut addr = [0u8; 4];
                unsafe {
                    std::ptr::copy_nonoverlapping(addr_ptr, addr.as_mut_ptr(), 4);
                }
                return Some(std::net::IpAddr::V4(Ipv4Addr::new(
                    addr[0], addr[1], addr[2], addr[3],
                )));
            }
        }

        cmsg = unsafe { libc::CMSG_NXTHDR(msghdr, cmsg) };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_recv_dst_ip() {
        let listener = UdpSocketWithDst::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener
            .async_fd
            .get_ref()
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap();

        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.send_to(b"hello", addr).unwrap();

        let result = timeout(Duration::from_secs(2), listener.recv_from()).await;
        assert!(result.is_ok());
        let (data, _src, dst) = result.unwrap().unwrap();
        assert_eq!(&data, b"hello");
        assert_eq!(dst.is_unspecified(), false);
    }
}
