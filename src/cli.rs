use clap::ArgAction;
use clap::Parser;

const PORTS_HEADING: &str = "Port Matching";

#[derive(Parser, Debug, Clone)]
#[command(author, about)]
pub struct Args {
    /// Sender pcap
    #[arg()]
    pub sndr_pcap: String,

    /// Sender pcap
    #[arg()]
    pub rcvr_pcap: String,

    /// Control how the resulting files are named
    #[arg(long)]
    pub name: Option<String>,

    /// Control how the resulting files are named
    #[arg(long, action = ArgAction::SetTrue)]
    pub split: bool,

    #[arg(long, help_heading = PORTS_HEADING)]
    pub iperf3_ports: Option<Vec<u16>>,

    #[arg(long, help_heading = PORTS_HEADING)]
    pub irtt_ports: Option<Vec<u16>>,
}
