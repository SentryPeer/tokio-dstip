// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Gavin Henry <ghenry@sentrypeer.org>

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd};
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_os = "macos")]
use nix::sys::socket::getsockname;
#[cfg(target_os = "macos")]
use socket2::SockAddr;

#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
use socket2::SockAddr;

pub struct TcpListenerWithDst {
    inner: TcpListener,
}

impl TcpListenerWithDst {
    /// Create a new listener bound to the given address
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { inner: listener })
    }

    /// Accept a connection and return (stream, peer_addr, destination_ip)
    pub async fn accept_with_dst(&self) -> std::io::Result<(TcpStream, SocketAddr, IpAddr)> {
        let (stream, peer_addr) = self.inner.accept().await?;
        let dst_ip = get_dst_ip(&stream)?;
        Ok((stream, peer_addr, dst_ip))
    }
}

fn get_dst_ip(stream: &TcpStream) -> std::io::Result<IpAddr> {
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut sockaddr = std::mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // Use getsockopt to retrieve the original destination
        let res = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                sockaddr.as_mut_ptr() as *mut _,
                &mut len,
            )
        };

        if res != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let sockaddr = unsafe { sockaddr.assume_init() };

        // Use socket2::SockAddr directly
        let sock_addr = unsafe { SockAddr::new(sockaddr, len as _) };

        sock_addr
            .as_socket()
            .map(|addr| addr.ip())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Invalid socket address"))
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, we use getsockname to get the local socket name
        let sockaddr =
            getsockname(fd).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Convert to socket2::SockAddr directly
        let sock_addr = SockAddr::from(sockaddr);

        // Extract the IP address from the socket address
        sock_addr
            .as_socket()
            .map(|addr| addr.ip())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Invalid socket address"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpStream as StdTcpStream;
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_accept_with_dst_ip() {
        let listener = TcpListenerWithDst::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let local_addr = listener.inner.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (mut stream, _peer, dst) = listener.accept_with_dst().await.unwrap();
            let mut buf = [0; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            assert_eq!(dst, local_addr.ip());
        });

        let mut client = StdTcpStream::connect(local_addr).unwrap();
        client.write_all(b"hello").unwrap();

        let _ = timeout(Duration::from_secs(2), handle).await;
    }
}
