use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    process::ExitCode,
    sync::mpsc,
    thread,
};

use anyhow::anyhow;
use anyhow::{Context, Result};
use clap::Parser;
use itertools::Itertools;
use pnet::packet::{
    Packet, ethernet::EtherTypes, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, sll2::SLL2Packet,
    udp::UdpPacket,
};

use libc::timeval;

mod cli;

#[inline(always)]
fn timeval_to_jiff(ts: timeval) -> jiff::Timestamp {
    let ns = ts.tv_usec * 1000;
    jiff::Timestamp::new(ts.tv_sec, ns.try_into().unwrap()).unwrap()
}

#[derive(Clone)]
struct SeqData {
    ts: timeval,
    size: u16,
}

trait FlowParser: Send {
    fn parse(&mut self, ts: timeval, size: u16, udp: &UdpPacket);

    fn get_seqs(&self) -> HashMap<u64, SeqData>;
}

#[derive(Default, Clone)]
struct Iperf3Udp {
    seqs: HashMap<u64, SeqData>,
}

impl FlowParser for Iperf3Udp {
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
        self.seqs.insert(seq, SeqData { ts, size });
    }

    fn get_seqs(&self) -> HashMap<u64, SeqData> {
        self.seqs.clone()
    }
}

#[derive(Default, Clone)]
struct Irtt {
    seqs: HashMap<u64, SeqData>,
}

/// IRTT Packet format (with hmac):
/// 0        4        8        12       16       20       24       28       32
/// magic fl ???      ???      ???      ???      conn token ???    seqno
/// 14a75b08 6023db39 486483de 51d86cde 57644032 18b2454b 21b6f281 12000000 000...
/// 14a75b08 bd63b501 1ed5e142 6dea9561 9e134506 18b2454b 21b6f281 13000000 000...
/// 14a75b08 13ac2779 6eb08c31 67bf3ee2 7d8abc0a 18b2454b 21b6f281 14000000 000...
impl FlowParser for Irtt {
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
        self.seqs.insert(seq, SeqData { ts, size });
    }

    fn get_seqs(&self) -> HashMap<u64, SeqData> {
        self.seqs.clone()
    }
}

type PortParserMap = HashMap<u16, Box<dyn FlowParser + Send>>;

fn prepare_port_map(args: &cli::Args) -> PortParserMap {
    let mut port_map: HashMap<u16, _> = HashMap::new();

    if let Some(ports) = args.iperf3.as_ref() {
        for port in ports {
            port_map.insert(
                *port,
                Box::new(Iperf3Udp::default()) as Box<dyn FlowParser + Send>,
            );
        }
    }

    if let Some(ports) = args.irtt.as_ref() {
        for port in ports {
            port_map.insert(
                *port,
                Box::new(Irtt::default()) as Box<dyn FlowParser + Send>,
            );
        }
    }

    port_map
}

fn parse_pcap(path: String, mut port_map: PortParserMap) -> Result<PortParserMap> {
    let mut cap = pcap::Capture::from_file(path).context("Failed opening pcap")?;

    let datalink = cap.get_datalink();
    if datalink != pcap::Linktype::LINUX_SLL2 {
        return Err(anyhow!(
            "Can't parse pcap datalink {:?}; currently only LINUX_SLL2 upported",
            datalink
        ));
    };

    while let Ok(packet) = cap.next_packet() {
        if let Some(sll2) = SLL2Packet::new(packet.data) {
            if sll2.get_protocol_type() == EtherTypes::Ipv4 {
                if let Some(ipv4) = Ipv4Packet::new(sll2.payload()) {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if let Some(parser) = port_map.get_mut(&udp.get_destination()) {
                                let ts = packet.header.ts;
                                let size = ipv4.get_total_length() + 20;
                                parser.parse(ts, size, &udp);
                            }
                        }
                    }
                }
            } else {
                eprintln!("unsupported sll2.protocol={}", sll2.get_protocol_type());
            }
        }
    }

    Ok(port_map)
}

type ResultMap = HashMap<u16, Vec<SeqResult>>;

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

fn match_parsers(sndr: PortParserMap, rcvr: PortParserMap) -> ResultMap {
    let mut results: ResultMap = HashMap::new();

    for (port, sndr_parser) in sndr.iter() {
        let mut port_result: Vec<SeqResult> = Vec::new();
        let rcvr_seqs = rcvr.get(port).unwrap().get_seqs();
        for (seq, sent) in sndr_parser.get_seqs().iter().sorted_by_key(|(k, _)| **k) {
            let mut res = SeqResult {
                ts_sent: timeval_to_jiff(sent.ts),
                ts_rcvd: jiff::Timestamp::new(0, 0).unwrap(),
                seq: *seq,
                owd_ms: -1.0,
                len: sent.size,
                lost: true,
            };
            if let Some(rcvd) = rcvr_seqs.get(seq) {
                res.ts_rcvd = timeval_to_jiff(rcvd.ts);
                let owd = timeval_to_jiff(rcvd.ts) - res.ts_sent;
                res.owd_ms = owd.total(jiff::Unit::Millisecond).unwrap();
                res.lost = false;
            };
            port_result.push(res);
        }
        results.insert(*port, port_result);
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
    let sndr_parsers = prepare_port_map(&args);
    let rcvr_parsers = prepare_port_map(&args);

    if sndr_parsers.len() == 0 {
        eprintln!("No ports passed");
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
