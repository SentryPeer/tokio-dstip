use tokio_dstip::UdpSocketWithDst;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let sock = UdpSocketWithDst::bind("0.0.0.0:8080".parse().unwrap())?;
    println!("Listening for UDP on 0.0.0.0:8080...");

    loop {
        let (data, src, dst) = sock.recv_from().await?;
        println!("From {src} to {dst}: {:?}", data);
    }
}
