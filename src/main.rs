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
use clap::Parser;
use itertools::Itertools;
use pcap::PacketHeader;
use pnet::packet::{
    Packet,
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    sll2::SLL2Packet,
    udp::UdpPacket,
};

use libc::timeval;

mod cli;

#[inline(always)]
fn timeval_to_jiff(ts: timeval) -> jiff::Timestamp {
    let ns = ts.tv_usec * 1000;
    jiff::Timestamp::new(ts.tv_sec, ns.try_into().unwrap()).unwrap()
}

type BoxedFlowParser = Box<dyn FlowParser + Send>;

enum FlowParsers {
    Iperf3Udp,
    Irtt,
}

impl FlowParsers {
    fn new(&self) -> BoxedFlowParser {
        match self {
            FlowParsers::Iperf3Udp => Box::new(Iperf3UdpParser::default()),
            FlowParsers::Irtt => Box::new(IrttParser::default()),
        }
    }
}

#[derive(Clone)]
struct PacketData {
    ts: timeval,
    size: u16,
}

trait FlowParser: Send {
    fn parse(&mut self, ts: timeval, size: u16, udp: &UdpPacket);

    fn get_packets(&self) -> &HashMap<u64, PacketData>;
}

#[derive(Default, Clone)]
struct Iperf3UdpParser {
    seqs: HashMap<u64, PacketData>,
}

impl FlowParser for Iperf3UdpParser {
    fn parse(&mut self, ts: timeval, size: u16, udp: &UdpPacket) {
        if udp.payload().len() < 12 {
            return;
        }
        let seq_bytes = &udp.payload()[8..12];
        let seq = u32::from_be_bytes(seq_bytes.try_into().unwrap()) as u64;
        if self.seqs.contains_key(&seq) {
            eprintln!(
                "iperf3 {}->{}: seq {} received twice",
                udp.get_source(),
                udp.get_destination(),
                seq
            );
            return;
        }
        self.seqs.insert(seq, PacketData { ts, size });
    }

    fn get_packets(&self) -> &HashMap<u64, PacketData> {
        &self.seqs
    }
}

#[derive(Default, Clone)]
struct IrttParser {
    seqs: HashMap<u64, PacketData>,
}

/// IRTT Packet format (with hmac):
/// 0        4        8        12       16       20       24       28       32
/// magic fl ???      ???      ???      ???      conn token ???    seqno
/// 14a75b08 6023db39 486483de 51d86cde 57644032 18b2454b 21b6f281 12000000 000...
/// 14a75b08 bd63b501 1ed5e142 6dea9561 9e134506 18b2454b 21b6f281 13000000 000...
/// 14a75b08 13ac2779 6eb08c31 67bf3ee2 7d8abc0a 18b2454b 21b6f281 14000000 000...
impl FlowParser for IrttParser {
    fn parse(&mut self, ts: timeval, size: u16, udp: &UdpPacket) {
        if udp.payload().len() < 32 {
            return;
        }

        let flags = udp.payload()[3];
        if !(flags == 8 || flags == 10) {
            return;
        }

        let seq_bytes = &udp.payload()[28..32];
        let seq = u32::from_le_bytes(seq_bytes.try_into().unwrap()) as u64;

        if self.seqs.contains_key(&seq) {
            eprintln!(
                "irtt {}->{}: seq {} received twice",
                udp.get_source(),
                udp.get_destination(),
                seq
            );
            return;
        }
        self.seqs.insert(seq, PacketData { ts, size });
    }

    fn get_packets(&self) -> &HashMap<u64, PacketData> {
        &self.seqs
    }
}

/// Can handle iperf3 and irtt packets. Should ideally be a trait on
/// the FlowParsers but I couldn't get it to work with Rust...
fn hashmap_match_with(
    sndr: &HashMap<u64, PacketData>,
    rcvr: &HashMap<u64, PacketData>,
) -> Vec<SeqResult> {
    let mut result: Vec<SeqResult> = Vec::new();

    for (seq, sent) in sndr.iter().sorted_by_key(|(k, _)| **k) {
        let mut res = SeqResult {
            ts_sent: timeval_to_jiff(sent.ts),
            ts_rcvd: jiff::Timestamp::new(0, 0).unwrap(),
            seq: *seq,
            owd_ms: f64::NAN,
            len: sent.size,
            lost: true,
        };
        if let Some(rcvd) = rcvr.get(seq) {
            res.ts_rcvd = timeval_to_jiff(rcvd.ts);
            let owd = timeval_to_jiff(rcvd.ts) - res.ts_sent;
            res.owd_ms = owd.total(jiff::Unit::Millisecond).unwrap();
            res.lost = false;
        };
        result.push(res);
    }

    result
}

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
enum PortType {
    Src,
    Dst,
}

#[derive(Default)]
struct ParserMatcher {
    map: HashMap<(PortType, SocketAddr), BoxedFlowParser>,
}

impl ParserMatcher {
    fn new(args: &cli::Args) -> ParserMatcher {
        let mut m = Self::default();

        m.add_addrs(&args.iperf3_udp_dst, PortType::Dst, FlowParsers::Iperf3Udp);
        m.add_addrs(&args.iperf3_udp_src, PortType::Src, FlowParsers::Iperf3Udp);
        m.add_addrs(&args.irtt_dst, PortType::Dst, FlowParsers::Irtt);
        m.add_addrs(&args.irtt_src, PortType::Src, FlowParsers::Irtt);

        m
    }

    fn add_addrs(
        &mut self,
        addrs: &Option<Vec<SocketAddr>>,
        port_type: PortType,
        parser: FlowParsers,
    ) {
        if let Some(addrs) = addrs {
            for addr in addrs {
                self.map.insert((port_type, *addr), parser.new());
            }
        }
    }

    fn match_packet(
        &mut self,
        ip_src: IpAddr,
        ip_dst: IpAddr,
        udp: &UdpPacket<'_>,
        ts: timeval,
        size: u16,
    ) {
        let ipv4_wildcard = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ipv6_wildcard = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        let dst_specific_addr = SocketAddr::new(ip_dst, udp.get_destination());
        let src_specific_addr = SocketAddr::new(ip_src, udp.get_source());

        let dst_v4_addr = SocketAddr::new(ipv4_wildcard, udp.get_destination());
        let src_v4_addr = SocketAddr::new(ipv4_wildcard, udp.get_source());
        let dst_v6_addr = SocketAddr::new(ipv6_wildcard, udp.get_destination());
        let src_v6_addr = SocketAddr::new(ipv6_wildcard, udp.get_source());

        let parser = if let Some(parser) = self.map.get_mut(&(PortType::Dst, dst_v4_addr)) {
            Some(parser)
        } else if let Some(parser) = self.map.get_mut(&(PortType::Src, src_v4_addr)) {
            Some(parser)
        } else if let Some(parser) = self.map.get_mut(&(PortType::Dst, dst_v6_addr)) {
            Some(parser)
        } else if let Some(parser) = self.map.get_mut(&(PortType::Src, src_v6_addr)) {
            Some(parser)
        } else if let Some(parser) = self.map.get_mut(&(PortType::Dst, dst_specific_addr)) {
            Some(parser)
        } else if let Some(parser) = self.map.get_mut(&(PortType::Src, src_specific_addr)) {
            Some(parser)
        } else {
            None
        };

        if let Some(parser) = parser {
            parser.parse(ts, size, udp);
        }
    }

    fn iter_parsers(&self) -> impl Iterator<Item = (&(PortType, SocketAddr), &BoxedFlowParser)> {
        self.map.iter()
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn get_parser(&self, key: &(PortType, SocketAddr)) -> Option<&BoxedFlowParser> {
        self.map.get(key)
    }
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
                    )?;
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
                    )?;
                } else {
                    eprintln!("Failed to assemble EthernetPacket");
                }
            }
            _ => {
                return Err(anyhow!(
                    "Can't parse pcap datalink {:?}; currently only LINUX_SLL2 upported",
                    datalink
                ));
            }
        };
    }
    Ok(parsers)
}

fn parse_packet(
    parsers: &mut ParserMatcher,
    header: &PacketHeader,
    eth_type: EtherType,
    payload: &[u8],
) -> Result<()> {
    let ts = header.ts;
    match eth_type {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(payload) {
                if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        let size = ipv4.get_total_length() + 20;
                        parsers.match_packet(
                            IpAddr::V4(ipv4.get_source()),
                            IpAddr::V4(ipv4.get_destination()),
                            &udp,
                            ts,
                            size,
                        );
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(payload) {
                if ipv6.get_next_header() == IpNextHeaderProtocols::Udp {
                    if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                        let size = ipv6.get_payload_length() + 40;
                        parsers.match_packet(
                            IpAddr::V6(ipv6.get_source()),
                            IpAddr::V6(ipv6.get_destination()),
                            &udp,
                            ts,
                            size,
                        );
                    }
                }
            }
        }
        _ => eprintln!("unsupported ether type={}", eth_type),
    };

    Ok(())
}

#[derive(Debug)]
struct SeqResult {
    ts_sent: jiff::Timestamp,
    ts_rcvd: jiff::Timestamp,
    seq: u64,
    owd_ms: f64,
    len: u16,
    lost: bool,
}

impl SeqResult {
    fn to_csv_row(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            self.ts_sent.to_string(),
            self.ts_rcvd.to_string(),
            self.seq,
            self.owd_ms,
            self.len,
            self.lost
        )
    }
}

type ResultMap = HashMap<u16, Vec<SeqResult>>;

fn match_parsers(sndr: ParserMatcher, rcvr: ParserMatcher) -> ResultMap {
    let mut results: ResultMap = HashMap::new();

    for (key, sndr_parser) in sndr.iter_parsers() {
        let rcvr_parser = rcvr.get_parser(key).unwrap();
        let result = hashmap_match_with(sndr_parser.get_packets(), rcvr_parser.get_packets());
        let negative_owd_count = result
            .iter()
            .filter(|r| f64::is_nan(r.owd_ms) && r.owd_ms < 0.0)
            .count();
        if negative_owd_count > 0 {
            eprintln!(
                "Port {}: encountered {} packets with negative latency",
                key.1.port(),
                negative_owd_count
            );
        }
        if let Some(_) = results.insert(key.1.port(), result) {
            eprintln!("Port {} parsed twice", key.1.port());
        }
    }

    results
}

fn write_out(args: &cli::Args, results: ResultMap) -> Result<()> {
    let name = args.name.clone().unwrap_or("default".to_string()); // TODO
    let base_path = PathBuf::from(args.sndr_pcap.clone());
    let base_path = base_path.parent().unwrap();

    let header = "ts_sent\tts_rcvd\tseq\tlatency_ms\tlen\tlost\n".as_bytes();

    for (port, seqs) in results.iter() {
        let file_name = format!("{name}.{port}.csv");
        let path_out = base_path.join(file_name);
        let f = File::create(path_out).context("Failed opening csv file for writing")?;
        let mut f = BufWriter::new(f);

        f.write(header).context("Failed writing csv header")?;

        for seq_result in seqs {
            f.write(seq_result.to_csv_row().as_bytes())?;
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let args = cli::Args::parse();

    let (tx_sndr, rx) = mpsc::channel();
    let tx_rcvr = tx_sndr.clone();

    let sndr_pcap = args.sndr_pcap.clone();
    let rcvr_pcap = args.rcvr_pcap.clone();
    let sndr_parsers = ParserMatcher::new(&args);
    let rcvr_parsers = ParserMatcher::new(&args);

    if sndr_parsers.len() == 0 {
        eprintln!("No addresses passed");
        return ExitCode::FAILURE;
    }

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

    let results = match_parsers(sndr_parsers.unwrap(), rcvr_parsers.unwrap());

    if let Err(e) = write_out(&args, results) {
        eprintln!("{}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
