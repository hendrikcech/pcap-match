use core::f64;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::mpsc,
    thread,
};

use anyhow::anyhow;
use anyhow::{Context, Result};
use pcap::PacketHeader;
use pnet::packet::{
    Packet,
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    sll2::SLL2Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};

use crate::{
    cli::Args,
    parsers::{AvailableFlowParsers, FlowParsers},
};

pub mod cli;
mod parsers;

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
enum PortType {
    Src,
    Dst,
}

#[derive(Default)]
/// Holds all configured FlowParsers and directs matching packets to them for parsing.
struct ParserMatcher {
    parsers: HashMap<(IpNextHeaderProtocol, PortType, SocketAddr), FlowParsers>,
}

impl ParserMatcher {
    fn new(args: cli::Args) -> ParserMatcher {
        let mut m = Self::default();

        m.add_addrs(
            &args.iperf3_udp_dst,
            IpNextHeaderProtocols::Udp,
            PortType::Dst,
            AvailableFlowParsers::Iperf3Udp,
        );
        m.add_addrs(
            &args.iperf3_udp_src,
            IpNextHeaderProtocols::Udp,
            PortType::Src,
            AvailableFlowParsers::Iperf3Udp,
        );
        m.add_addrs(
            &args.irtt_dst,
            IpNextHeaderProtocols::Udp,
            PortType::Dst,
            AvailableFlowParsers::Irtt,
        );
        m.add_addrs(
            &args.irtt_src,
            IpNextHeaderProtocols::Udp,
            PortType::Src,
            AvailableFlowParsers::Irtt,
        );
        m.add_addrs(
            &args.netmeas_dst,
            IpNextHeaderProtocols::Udp,
            PortType::Dst,
            AvailableFlowParsers::Netmeas,
        );
        m.add_addrs(
            &args.netmeas_src,
            IpNextHeaderProtocols::Udp,
            PortType::Src,
            AvailableFlowParsers::Netmeas,
        );
        m.add_addrs(
            &args.tcp_dst,
            IpNextHeaderProtocols::Tcp,
            PortType::Dst,
            AvailableFlowParsers::Tcp,
        );
        m.add_addrs(
            &args.tcp_src,
            IpNextHeaderProtocols::Tcp,
            PortType::Src,
            AvailableFlowParsers::Tcp,
        );

        m
    }

    fn add_addrs(
        &mut self,
        addrs: &Option<Vec<SocketAddr>>,
        proto: IpNextHeaderProtocol,
        port_type: PortType,
        parser: AvailableFlowParsers,
    ) {
        if let Some(addrs) = addrs {
            for addr in addrs {
                // eprintln!("Add parser {proto} {port_type:?} {parser:?} {addrs:?}");
                self.parsers
                    .insert((proto, port_type, *addr), parser.into());
            }
        }
    }

    fn get_map_keys(
        proto: IpNextHeaderProtocol,
        ip_src: IpAddr,
        ip_dst: IpAddr,
        port_src: u16,
        port_dst: u16,
    ) -> [(IpNextHeaderProtocol, PortType, SocketAddr); 6] {
        let ipv4_wildcard = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ipv6_wildcard = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        let dst_specific_addr = SocketAddr::new(ip_dst, port_dst);
        let src_specific_addr = SocketAddr::new(ip_src, port_src);

        let dst_v4_addr = SocketAddr::new(ipv4_wildcard, port_dst);
        let src_v4_addr = SocketAddr::new(ipv4_wildcard, port_src);
        let dst_v6_addr = SocketAddr::new(ipv6_wildcard, port_dst);
        let src_v6_addr = SocketAddr::new(ipv6_wildcard, port_src);

        [
            (proto, PortType::Dst, dst_v4_addr),
            (proto, PortType::Src, src_v4_addr),
            (proto, PortType::Dst, dst_v6_addr),
            (proto, PortType::Src, src_v6_addr),
            (proto, PortType::Dst, dst_specific_addr),
            (proto, PortType::Src, src_specific_addr),
        ]
    }

    fn match_packet(
        &mut self,
        proto: IpNextHeaderProtocol,
        payload: &[u8],
        ip_src: IpAddr,
        ip_dst: IpAddr,
        ts: jiff::Timestamp,
        size: u16,
    ) {
        match proto {
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    let keys = Self::get_map_keys(
                        proto,
                        ip_src,
                        ip_dst,
                        udp.get_source(),
                        udp.get_destination(),
                    );
                    for key in keys {
                        if let Some(parser) = self.parsers.get_mut(&key) {
                            parser.parse_udp(ts, size, &udp);
                        }
                    }
                }
            }
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    let keys = Self::get_map_keys(
                        proto,
                        ip_src,
                        ip_dst,
                        tcp.get_source(),
                        tcp.get_destination(),
                    );
                    for key in keys {
                        if let Some(parser) = self.parsers.get_mut(&key) {
                            parser.parse_tcp(ts, size, &tcp);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn iter_parsers(
        &self,
    ) -> impl Iterator<Item = (&(IpNextHeaderProtocol, PortType, SocketAddr), &FlowParsers)> {
        self.parsers.iter()
    }

    fn len(&self) -> usize {
        self.parsers.len()
    }

    fn get_parser(
        &self,
        key: &(IpNextHeaderProtocol, PortType, SocketAddr),
    ) -> Option<&FlowParsers> {
        self.parsers.get(key)
    }
}

fn parse_packet(
    parsers: &mut ParserMatcher,
    header: &PacketHeader,
    eth_type: EtherType,
    payload: &[u8],
) {
    let ts = parsers::timeval_to_jiff(header.ts);
    match eth_type {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(payload)
                && (ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp
                    || ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp)
            {
                let size = ipv4.get_total_length() + 20;
                parsers.match_packet(
                    ipv4.get_next_level_protocol(),
                    ipv4.payload(),
                    IpAddr::V4(ipv4.get_source()),
                    IpAddr::V4(ipv4.get_destination()),
                    ts,
                    size,
                );
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(payload)
                && (ipv6.get_next_header() == IpNextHeaderProtocols::Udp
                    || ipv6.get_next_header() == IpNextHeaderProtocols::Tcp)
            {
                let size = ipv6.get_payload_length() + 40;
                parsers.match_packet(
                    ipv6.get_next_header(),
                    ipv6.payload(),
                    IpAddr::V6(ipv6.get_source()),
                    IpAddr::V6(ipv6.get_destination()),
                    ts,
                    size,
                );
            }
        }
        EtherTypes::Arp => (),
        _ => eprintln!("unsupported ether type={}", eth_type),
    };
}

fn parse_pcap(path: String, mut parsers: ParserMatcher) -> Result<ParserMatcher> {
    let mut cap = pcap::Capture::from_file(path).context("Failed opening pcap")?;

    let datalink = cap.get_datalink();

    while let Ok(packet) = cap.next_packet() {
        match datalink {
            pcap::Linktype::LINUX_SLL2 => {
                if let Some(sll2) = SLL2Packet::new(packet.data) {
                    parse_packet(
                        &mut parsers,
                        packet.header,
                        sll2.get_protocol_type(),
                        sll2.payload(),
                    );
                } else {
                    eprintln!("Failed to assemble SSL2Packet");
                }
            }
            pcap::Linktype::ETHERNET => {
                if let Some(eth) = EthernetPacket::new(packet.data) {
                    parse_packet(
                        &mut parsers,
                        packet.header,
                        eth.get_ethertype(),
                        eth.payload(),
                    );
                } else {
                    eprintln!("Failed to assemble EthernetPacket");
                }
            }
            pcap::Linktype::RAW | pcap::Linktype(12) => {
                if packet.data.is_empty() {
                    continue;
                }
                let ether_type = match packet.data[0] >> 4 {
                    4 => EtherTypes::Ipv4,
                    6 => EtherTypes::Ipv6,
                    _ => {
                        eprintln!("Unknown IP version");
                        continue;
                    }
                };
                parse_packet(&mut parsers, packet.header, ether_type, packet.data);
            }
            _ => {
                return Err(anyhow!(
                    "Can't parse pcap {:?} {:?} ({:?}); currently only LINUX_SLL2 and ETHERNET upported",
                    datalink,
                    datalink.get_name(),
                    datalink.get_description(),
                ));
            }
        };
    }
    Ok(parsers)
}

#[derive(Debug)]
struct SeqResult {
    ts_sent: jiff::Timestamp,
    ts_rcvd: Option<jiff::Timestamp>,
    seq: u64,
    owd_ms: Option<f64>,
    size: u16,
    lost: bool,
}

// Legacy
// let header = "ts_sent\tts_rcvd\tseq\tlatency_ms\tlen\tlost\n".as_bytes();
const CSV_HEADER: &[u8] = "seq,ts_sent,ts_rcvd,owd_ms,size,lost\n".as_bytes();

impl SeqResult {
    fn to_csv_row(&self) -> String {
        let ts_rcvd = self.ts_rcvd.map_or("".to_string(), |ts| ts.to_string());
        let owd_ms = self
            .owd_ms
            .map_or("".to_string(), |owd_ms| owd_ms.to_string());
        format!(
            "{},{},{},{},{},{}\n",
            self.seq, self.ts_sent, ts_rcvd, owd_ms, self.size, self.lost
        )
    }

    // Legacy format
    // fn to_csv_row(&self) -> String {
    //     format!(
    //         "{}\t{}\t{}\t{}\t{}\t{}\n",
    //         self.ts_sent, self.ts_rcvd, self.seq, self.owd_ms, self.len, self.lost
    //     )
    // }
}

type ResultMap = HashMap<u16, Vec<SeqResult>>;

fn match_parsers(sndr: ParserMatcher, rcvr: ParserMatcher) -> ResultMap {
    let mut results: ResultMap = HashMap::new();

    for (key, sndr_parser) in sndr.iter_parsers() {
        let rcvr_parser = rcvr.get_parser(key).unwrap();
        let result = sndr_parser.match_with_rcvr(rcvr_parser);
        let negative_owd_count = result
            .iter()
            .filter(|r| r.owd_ms.is_some_and(|owd_ms| owd_ms < 0.0))
            .count();
        if negative_owd_count > 0 {
            eprintln!(
                "Port {}: encountered {} packets with negative latency",
                key.2.port(),
                negative_owd_count
            );
        }
        if results.insert(key.2.port(), result).is_some() {
            eprintln!("Port {} parsed twice", key.2.port());
        }
    }

    results
}

fn write_out(args: &cli::Args, results: ResultMap) -> Result<()> {
    let name = args.name.clone().unwrap_or("default".to_string()); // TODO
    let base_path = PathBuf::from(args.sndr_pcap.clone());
    let base_path = base_path.parent().unwrap();

    for (port, seqs) in results.iter() {
        let file_name = format!("{name}.{port}.csv");
        let path_out = base_path.join(file_name);
        eprintln!(
            "Write {} rows to {}",
            seqs.len(),
            path_out.to_string_lossy()
        );
        let f = File::create(path_out).context("Failed opening csv file for writing")?;
        let mut f = BufWriter::new(f);

        f.write(CSV_HEADER).context("Failed writing csv header")?;

        for seq_result in seqs {
            f.write_all(seq_result.to_csv_row().as_bytes())?;
        }
    }

    Ok(())
}

pub fn run_args(args: Args) -> ExitCode {
    let (tx_sndr, rx) = mpsc::channel();
    let tx_rcvr = tx_sndr.clone();

    let sndr_pcap = args.sndr_pcap.clone();
    let rcvr_pcap = args.rcvr_pcap.clone();

    // Turn passed arguments into individual FlowParsers stored in ParserMatcher
    let sndr_parsers = ParserMatcher::new(args.clone());
    let rcvr_parsers = ParserMatcher::new(args.clone());

    if sndr_parsers.len() == 0 {
        eprintln!("No addresses passed");
        return ExitCode::FAILURE;
    }

    // Parse packets from pcaps in parallel
    thread::spawn(move || {
        eprintln!("Parsing {}", sndr_pcap);
        let parsers = parse_pcap(sndr_pcap, sndr_parsers);
        tx_sndr.send(("sndr", parsers)).unwrap();
    });
    thread::spawn(move || {
        eprintln!("Parsing {}", rcvr_pcap);
        let parsers = parse_pcap(rcvr_pcap, rcvr_parsers);
        tx_rcvr.send(("rcvr", parsers)).unwrap();
    });

    // Wait until both parsers have finished and match them back to sndr and rcvr
    let mut sndr_parsers = None;
    let mut rcvr_parsers = None;
    while sndr_parsers.is_none() || rcvr_parsers.is_none() {
        match rx.recv().unwrap() {
            (name, Err(e)) => {
                eprintln!("Parsing {}: {}", name, e);
                return ExitCode::FAILURE;
            }
            ("sndr", Ok(v)) => sndr_parsers = Some(v),
            ("rcvr", Ok(v)) => rcvr_parsers = Some(v),
            _ => panic!("Should be unreachable"),
        }
    }

    // Match sent and received packets
    let results = match_parsers(sndr_parsers.unwrap(), rcvr_parsers.unwrap());

    // Output matches in csv format
    if let Err(e) = write_out(&args, results) {
        eprintln!("{}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
