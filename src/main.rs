use std::process::ExitCode;

use clap::Parser;
use pcap_match::{cli, run_args};

fn main() -> ExitCode {
    let args = cli::Args::parse();
    run_args(args)
}
