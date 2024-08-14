use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;

mod gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt)]
struct Cli {
    //这里会默认使用--address作为long，不指定short就会使用字段的首字母
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long)]
    output: PathBuf,

    //index表明当前生成的是第几个私钥片段。
    #[structopt(short, long)]
    index: u16,
    //这里阈值就是要有多少个以上的人对这个信息进行签名，eg t = 1,则需要两个人。
    #[structopt(short, long)]
    threshold: u16,
    //number_of_parties是指代有多少个人持有私钥
    #[structopt(short, long)]
    number_of_parties: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)
        .await
        //下面的?用于简化错误处理，如果操作失败，会将错误返回调用者，输出对应的内容
        .context("cannot create output file")?;

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;
    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    tokio::io::copy(&mut output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;

    Ok(())
}
