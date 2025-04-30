# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-04-30

### Changes
- Added missing functions that we use in the original `tokio::net` APIs to 
`TcpListenerWithDst` and `UdpSocketWithDst`:
  - `TcpListenerWithDst::local_addr`
  - `UdpSocketWithDst::local_addr`
  - `UdpSocketWithDst::send_to`

## [0.1.0] - 2025-04-27

- Initial release
