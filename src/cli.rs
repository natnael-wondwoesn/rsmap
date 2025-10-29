use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;

#[derive(Parser, Debug)]
#[command(name = "rsmap", about = "AI-powered port scanner")]
pub struct Args {
    // #[args(value_parser = utils::ip::parse_ip)]
    pub target: IpAddr,

    // #[arg(short, long, value_parser = utils::ports::parse_ports, default_value = "1-1024")]
    pub ports: Vec<u16>,

    // #[arg(long)]
    pub explain: bool,

    // #[arg(short,long,action = clap::ArgAction::Count)]
    pub verbose: u8,
    // #[arg(short,long,value_enum,default_value="text")]
    // pub output: OutputFormat

    // #[command(subcommand)]
    // pub command: Option<Command>,
}
