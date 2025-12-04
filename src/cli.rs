use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;

use clap::ArgAction;
use clap::Parser;

const MATCHING_HEADING: &str = "Packet Matching";

#[derive(Parser, Debug, Clone)]
#[command(author, about)]
pub struct Args {
    /// Sender pcap
    #[arg()]
    pub sndr_pcap: String,

    /// Receiver pcap
    #[arg()]
    pub rcvr_pcap: String,

    /// Control how the resulting files are named
    #[arg(long)]
    pub name: Option<String>,

    /// Control how the resulting files are named
    #[arg(long, action = ArgAction::SetTrue)]
    pub split: bool,

    /// Match these iperf3 (UDP mode) destination ports (or address:port)
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=parse_matcher)]
    pub iperf3_udp_dst: Option<Vec<SocketAddr>>,

    /// Match these iperf3 (UDP mode) source ports (or address:port)
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=parse_matcher)]
    pub iperf3_udp_src: Option<Vec<SocketAddr>>,

    /// Match these IRTT destination ports (or address:port)
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=parse_matcher)]
    pub irtt_dst: Option<Vec<SocketAddr>>,

    /// Match these IRTT source ports (or address:port)
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=parse_matcher)]
    pub irtt_src: Option<Vec<SocketAddr>>,

    /// Match these iperf3 (TCP mode) destination ports (or address:port)
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=parse_matcher)]
    pub iperf3_tcp_dst: Option<Vec<SocketAddr>>,

    /// Match these iperf3 (TCP mode) source ports (or address:port)
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=parse_matcher)]
    pub iperf3_tcp_src: Option<Vec<SocketAddr>>,

    /// Match only packets with this destination IP address
    #[arg(long, help_heading = MATCHING_HEADING, value_parser=IpAddr::from_str)]
    pub dst_ip: Option<IpAddr>,
}

/// Valid:
/// 8000 (port-only)
/// 10.0.1.1:8000 (address and port)
fn parse_matcher(s: &str) -> Result<SocketAddr> {
    if let Ok(port) = u16::from_str(s) {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
    } else {
        SocketAddr::from_str(s).context("Failed to parse argument as port or IP:port")
    }
}
