// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Gavin Henry <ghenry@sentrypeer.org>

use std::io::IoSliceMut;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, RecvMsg, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

/// Platform abstraction
#[cfg(target_os = "linux")]
fn enable_pktinfo(fd: i32, ipv6: bool) {
    if ipv6 {
        setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true).expect("IPV6_PKTINFO failed");
    } else {
        setsockopt(fd, sockopt::Ipv4PacketInfo, &true).expect("IP_PKTINFO failed");
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
        let mut cmsgspace = nix::cmsg_space!([u8; 128]); // enough for control messages
        let iov = [IoSliceMut::new(&mut buf)];

        loop {
            let mut guard = self.async_fd.readable().await?;
            let raw_fd = guard.as_raw_fd();
            match recvmsg::<SockaddrStorage>(raw_fd, &iov, Some(&mut cmsgspace), MsgFlags::empty())
            {
                Ok(msg) => {
                    let source = msg.address.expect("Missing source address");
                    let data = buf[..msg.bytes].to_vec();
                    let dst_ip = extract_dst_ip(&msg).unwrap_or(std::net::IpAddr::UNSPECIFIED);
                    return Ok((data, sockaddr_to_std(&source), dst_ip));
                }
                Err(e) if e == nix::errno::Errno::EWOULDBLOCK => continue,
                Err(e) => return Err(std::io::Error::from(e)),
            }
        }
    }
}

fn sockaddr_to_std(addr: &SockaddrStorage) -> SocketAddr {
    nix::sys::socket::Sockaddr::from(*addr)
        .as_socket()
        .expect("Not a socket address")
}

fn extract_dst_ip(msg: &RecvMsg) -> Option<std::net::IpAddr> {
    for cmsg in msg.cmsgs() {
        match cmsg {
            #[cfg(target_os = "linux")]
            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                return Some(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()).into());
            }
            #[cfg(target_os = "linux")]
            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                return Some(pktinfo.ipi6_addr.into());
            }
            #[cfg(target_os = "macos")]
            ControlMessageOwned::Other(libc::IP_RECVDSTADDR, data) => {
                if data.len() == 4 {
                    return Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).into());
                }
            }
            _ => {}
        }
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
        let (data, src, dst) = result.unwrap().unwrap();
        assert_eq!(&data, b"hello");
        assert_eq!(dst.is_unspecified(), false);
    }
}
