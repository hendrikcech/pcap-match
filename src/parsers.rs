use std::{collections::HashMap, ops::Deref};

use pnet::packet::{Packet, tcp::TcpPacket, udp::UdpPacket};

use libc::timeval;

use crate::SeqResult;
use itertools::Itertools;

#[derive(Clone, Copy)]
pub enum AvailableFlowParsers {
    Iperf3Udp,
    Irtt,
    Iperf3Tcp,
}

pub enum FlowParsers {
    Iperf3Udp(Box<dyn for<'a> FlowParser<'a, Packet = UdpPacket<'a>, Key = u64>>),
    Irtt(Box<dyn for<'a> FlowParser<'a, Packet = UdpPacket<'a>, Key = u64>>),
    Iperf3Tcp(Box<dyn for<'a> FlowParser<'a, Packet = TcpPacket<'a>, Key = u64>>),
}

impl From<AvailableFlowParsers> for FlowParsers {
    fn from(v: AvailableFlowParsers) -> Self {
        match v {
            AvailableFlowParsers::Iperf3Udp => {
                FlowParsers::Iperf3Udp(Box::new(Iperf3UdpParser::default()))
            }
            AvailableFlowParsers::Irtt => FlowParsers::Irtt(Box::new(IrttParser::default())),
            AvailableFlowParsers::Iperf3Tcp => {
                FlowParsers::Iperf3Tcp(Box::new(Iperf3TcpParser::default()))
            }
        }
    }
}

impl FlowParsers {
    pub fn parse_udp(&mut self, ts: timeval, size: u16, packet: &UdpPacket) {
        match self {
            FlowParsers::Iperf3Udp(p) => p.parse(ts, size, packet),
            FlowParsers::Irtt(p) => p.parse(ts, size, packet),
            FlowParsers::Iperf3Tcp(_) => unreachable!(),
        }
    }

    pub fn parse_tcp(&mut self, ts: timeval, size: u16, packet: &TcpPacket) {
        match self {
            FlowParsers::Iperf3Udp(_) => unreachable!(),
            FlowParsers::Irtt(_) => unreachable!(),
            FlowParsers::Iperf3Tcp(p) => p.parse(ts, size, packet),
        }
    }

    pub fn match_with(&self, other: &FlowParsers) -> Vec<SeqResult> {
        match (self, other) {
            (FlowParsers::Iperf3Udp(a), FlowParsers::Iperf3Udp(b)) => a.match_with(b.deref()),
            (FlowParsers::Irtt(a), FlowParsers::Irtt(b)) => a.match_with(b.deref()),
            (FlowParsers::Iperf3Tcp(a), FlowParsers::Iperf3Tcp(b)) => a.match_with(b.deref()),
            _ => unreachable!(),
        }
    }
}

pub trait FlowParser<'a>: Send {
    type Packet: Packet;
    type Key;

    fn parse(&mut self, ts: timeval, size: u16, packet: &Self::Packet);

    fn get_packets(&self) -> &HashMap<Self::Key, PacketData>;

    fn match_with(
        &self,
        other: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult>;
}

#[derive(Clone)]
/// Metadata of each parsed packet used for matching.
pub struct PacketData {
    ts: timeval,
    size: u16,
}

#[inline(always)]
fn timeval_to_jiff(ts: timeval) -> jiff::Timestamp {
    let ns = ts.tv_usec * 1000;
    jiff::Timestamp::new(ts.tv_sec, ns.try_into().unwrap()).unwrap()
}

/// Can handle iperf3 UDP and irtt packets.
fn hashmap_match_u64(
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

#[derive(Default, Clone)]
struct Iperf3UdpParser {
    seqs: HashMap<u64, PacketData>,
}

impl<'a> FlowParser<'a> for Iperf3UdpParser {
    type Packet = UdpPacket<'a>;
    type Key = u64;

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

    fn get_packets(&self) -> &HashMap<Self::Key, PacketData> {
        &self.seqs
    }

    fn match_with(
        &self,
        other: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        hashmap_match_u64(self.get_packets(), other.get_packets())
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
impl<'a> FlowParser<'a> for IrttParser {
    type Packet = UdpPacket<'a>;
    type Key = u64;

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

    fn get_packets(&self) -> &HashMap<Self::Key, PacketData> {
        &self.seqs
    }

    fn match_with(
        &self,
        other: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        hashmap_match_u64(self.get_packets(), other.get_packets())
    }
}

#[derive(Default, Clone)]
struct Iperf3TcpParser {
    seqs: HashMap<u64, PacketData>,
}

impl<'a> FlowParser<'a> for Iperf3TcpParser {
    type Packet = TcpPacket<'a>;
    type Key = u64;

    fn parse(&mut self, _ts: timeval, _size: u16, _packet: &TcpPacket) {
        todo!()
        // tcp.get_sequence()
        // tcp.get

        // self.seqs.insert(seq, PacketData { ts, size });
    }

    fn get_packets(&self) -> &HashMap<Self::Key, PacketData> {
        &self.seqs
    }

    fn match_with(
        &self,
        _other: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        todo!()
        // hashmap_match_with(self.get_packets(), other.get_packets())
    }
}
