# tokio-dstip

Get a packet's destination IP address whilst using Tokio on Linux and macOS

## Features
- **UDP** destination IP address from incoming packets (Linux + macOS)
- **TCP** destination IP address for accepted connections (Linux + macOS)
- Native `tokio::net` compatibility
- TLS-friendly: works with `tokio_rustls` and other wrappers

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![CI][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/tokio-dstip.svg
[crates-url]: https://crates.io/crates/tokio-dstip
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/SentryPeer/tokio-dstip/blob/main/LICENSE
[actions-badge]: https://github.com/SentryPeer/tokio-dstip/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/SentryPeer/tokio-dstip/actions/workflows/ci.yml

## Install
```toml
[dependencies]
tokio-dstip = "0.1"
```

## Usage

### TCP
```rust
use tokio_dstip::TcpListenerWithDst;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListenerWithDst::bind("127.0.0.1:8080".parse().unwrap()).await?;
    let (stream, peer, dst_ip) = listener.accept_with_dst().await?;
    println!("Received from {peer}, destined to {dst_ip}");
    Ok(())
}
```

### UDP
```rust
use tokio_dstip::UdpSocketWithDst;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let sock = UdpSocketWithDst::bind("0.0.0.0:8080".parse().unwrap())?;
    let (data, source, dst_ip) = sock.recv_from().await?;
    println!("UDP from {source}, destined to {dst_ip}: {:?}", data);
    Ok(())
}
```

## Examples
```bash
cargo run --example udp
cargo run --example tcp
```

## License
MIT
