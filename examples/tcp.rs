use tokio::io::AsyncReadExt;
use tokio_dstip::TcpListenerWithDst;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListenerWithDst::bind("0.0.0.0:8080".parse().unwrap()).await?;
    println!("Listening for TCP on 0.0.0.0:8080...");

    loop {
        let (mut stream, peer, dst) = listener.accept_with_dst().await?;
        println!("Accepted from {peer}, destined to {dst}");

        let mut buf = vec![0; 1024];
        let n = stream.read(&mut buf).await?;
        println!("Read {} bytes: {:?}", n, &buf[..n]);
    }
}
