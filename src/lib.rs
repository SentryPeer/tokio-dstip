// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Gavin Henry <ghenry@sentrypeer.org>

//! tokio-dstip: Get a packet's destination IP address whilst using Tokio on Linux and macOS

pub mod tcp;
pub mod udp;

pub use tcp::TcpListenerWithDst;
pub use udp::UdpSocketWithDst;
