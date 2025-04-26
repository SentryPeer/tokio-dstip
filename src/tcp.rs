// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Gavin Henry <ghenry@sentrypeer.org>

use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_os = "macos")]
use nix::sys::socket::getsockname;
#[cfg(target_os = "macos")]
use socket2::SockAddr;

#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::OriginalDst};

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
    let raw_fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let sockaddr = getsockopt(raw_fd, OriginalDst)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(sockaddr.ip())
    }

    #[cfg(target_os = "macos")]
    {
        let sockaddr =
            getsockname(raw_fd).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let std_addr = SockAddr::from(sockaddr).as_socket().unwrap();
        Ok(std_addr.ip())
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
