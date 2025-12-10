use std::{collections::HashMap, ops::Deref};

use pnet::packet::{
    Packet,
    tcp::{TcpFlags, TcpOptionNumbers, TcpPacket},
    udp::UdpPacket,
};

use libc::timeval;

use crate::SeqResult;
use itertools::Itertools;

#[derive(Clone, Copy, Debug)]
pub enum AvailableFlowParsers {
    Iperf3Udp,
    Irtt,
    Tcp,
    Netmeas,
}

pub enum FlowParsers {
    Iperf3Udp(Box<dyn for<'a> FlowParser<'a, Packet = UdpPacket<'a>, Key = u64>>),
    Irtt(Box<dyn for<'a> FlowParser<'a, Packet = UdpPacket<'a>, Key = u64>>),
    Netmeas(Box<dyn for<'a> FlowParser<'a, Packet = UdpPacket<'a>, Key = u64>>),
    Tcp(Box<dyn for<'a> FlowParser<'a, Packet = TcpPacket<'a>, Key = TcpKey>>),
}

impl From<AvailableFlowParsers> for FlowParsers {
    fn from(v: AvailableFlowParsers) -> Self {
        match v {
            AvailableFlowParsers::Iperf3Udp => {
                FlowParsers::Iperf3Udp(Box::new(Iperf3UdpParser::default()))
            }
            AvailableFlowParsers::Irtt => FlowParsers::Irtt(Box::new(IrttParser::default())),
            AvailableFlowParsers::Netmeas => {
                FlowParsers::Netmeas(Box::new(NetmeasParser::default()))
            }
            AvailableFlowParsers::Tcp => FlowParsers::Tcp(Box::new(Iperf3TcpParser::default())),
        }
    }
}

impl FlowParsers {
    pub fn parse_udp(&mut self, ts: jiff::Timestamp, size: u16, packet: &UdpPacket) {
        match self {
            FlowParsers::Iperf3Udp(p) => p.parse(ts, size, packet),
            FlowParsers::Irtt(p) => p.parse(ts, size, packet),
            FlowParsers::Netmeas(p) => p.parse(ts, size, packet),
            FlowParsers::Tcp(_) => unreachable!(),
        }
    }

    pub fn parse_tcp(&mut self, ts: jiff::Timestamp, size: u16, packet: &TcpPacket) {
        match self {
            FlowParsers::Iperf3Udp(_) => unreachable!(),
            FlowParsers::Irtt(_) => unreachable!(),
            FlowParsers::Netmeas(_) => unreachable!(),
            FlowParsers::Tcp(p) => p.parse(ts, size, packet),
        }
    }

    pub fn match_with_rcvr(&self, rcvr: &FlowParsers) -> Vec<SeqResult> {
        match (self, rcvr) {
            (FlowParsers::Iperf3Udp(a), FlowParsers::Iperf3Udp(b)) => a.match_with_rcvr(b.deref()),
            (FlowParsers::Irtt(a), FlowParsers::Irtt(b)) => a.match_with_rcvr(b.deref()),
            (FlowParsers::Netmeas(a), FlowParsers::Netmeas(b)) => a.match_with_rcvr(b.deref()),
            (FlowParsers::Tcp(a), FlowParsers::Tcp(b)) => a.match_with_rcvr(b.deref()),

            (FlowParsers::Iperf3Udp(_), FlowParsers::Irtt(_)) => unreachable!(),
            (FlowParsers::Iperf3Udp(_), FlowParsers::Netmeas(_)) => unreachable!(),
            (FlowParsers::Iperf3Udp(_), FlowParsers::Tcp(_)) => unreachable!(),
            (FlowParsers::Irtt(_), FlowParsers::Iperf3Udp(_)) => unreachable!(),
            (FlowParsers::Irtt(_), FlowParsers::Netmeas(_)) => unreachable!(),
            (FlowParsers::Irtt(_), FlowParsers::Tcp(_)) => unreachable!(),
            (FlowParsers::Netmeas(_), FlowParsers::Iperf3Udp(_)) => unreachable!(),
            (FlowParsers::Netmeas(_), FlowParsers::Irtt(_)) => unreachable!(),
            (FlowParsers::Netmeas(_), FlowParsers::Tcp(_)) => unreachable!(),
            (FlowParsers::Tcp(_), FlowParsers::Iperf3Udp(_)) => unreachable!(),
            (FlowParsers::Tcp(_), FlowParsers::Irtt(_)) => unreachable!(),
            (FlowParsers::Tcp(_), FlowParsers::Netmeas(_)) => unreachable!(),
        }
    }
}

pub trait FlowParser<'a>: Send {
    type Packet: Packet;
    type Key;

    fn parse(&mut self, ts: jiff::Timestamp, size: u16, packet: &Self::Packet);

    fn get_packets(&self) -> &HashMap<Self::Key, PacketData>;

    fn match_with_rcvr(
        &self,
        rcvr: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult>;
}

#[derive(Clone)]
/// Metadata of each parsed packet used for matching.
pub struct PacketData {
    ts: jiff::Timestamp,
    size: u16,
}

#[inline(always)]
pub fn timeval_to_jiff(ts: timeval) -> jiff::Timestamp {
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
            ts_sent: sent.ts,
            ts_rcvd: None,
            seq: *seq,
            owd_ms: None,
            size: sent.size,
            lost: true,
        };
        if let Some(rcvd) = rcvr.get(seq) {
            res.ts_rcvd = Some(rcvd.ts);
            let owd = rcvd.ts - res.ts_sent;
            res.owd_ms = Some(owd.total(jiff::Unit::Millisecond).unwrap());
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

    fn parse(&mut self, ts: jiff::Timestamp, size: u16, udp: &UdpPacket) {
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

    fn match_with_rcvr(
        &self,
        rcvr: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        hashmap_match_u64(self.get_packets(), rcvr.get_packets())
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

    fn parse(&mut self, ts: jiff::Timestamp, size: u16, udp: &UdpPacket) {
        if udp.payload().len() < 32 {
            return;
        }

        // TODO: IRTT seems to be broken currently
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

    fn match_with_rcvr(
        &self,
        rcvr: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        hashmap_match_u64(self.get_packets(), rcvr.get_packets())
    }
}

#[derive(Default, Clone)]
struct NetmeasParser {
    seqs: HashMap<u64, PacketData>,
}

/// Netmeas format
/// u64 id in first 8 byte
impl<'a> FlowParser<'a> for NetmeasParser {
    type Packet = UdpPacket<'a>;
    type Key = u64;

    fn parse(&mut self, ts: jiff::Timestamp, size: u16, udp: &UdpPacket) {
        if udp.payload().len() < 8 {
            return;
        }

        let seq_bytes = &udp.payload()[..8];
        let seq = u64::from_be_bytes(seq_bytes.try_into().unwrap());

        if self.seqs.contains_key(&seq) {
            eprintln!(
                "netmeas {}->{}: seq {} received twice",
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

    fn match_with_rcvr(
        &self,
        rcvr: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        hashmap_match_u64(self.get_packets(), rcvr.get_packets())
    }
}

#[derive(Default, Clone)]
struct Iperf3TcpParser {
    seqs: HashMap<TcpKey, PacketData>,
}

/// Key used to match TCP packets.
/// Can't use checksum since it takes the IP addresses into account which are often NATed.
/// sequence number, ack seq num, flags, TCP timestamp option (ts_val + ts_ecr)
type TcpKey = (u32, u32, u8, u64);

impl<'a> FlowParser<'a> for Iperf3TcpParser {
    type Packet = TcpPacket<'a>;
    type Key = TcpKey;

    fn parse(&mut self, ts: jiff::Timestamp, size: u16, packet: &TcpPacket) {
        let packet_seq = packet.get_sequence();
        let packet_ack = packet.get_acknowledgement();

        // let checksum = packet.get_checksum();
        let flags = packet.get_flags();

        let ts_sum = if let Some(opt) = packet
            .get_options_iter()
            .find(|opt| opt.get_number() == TcpOptionNumbers::TIMESTAMPS)
        {
            let payload = opt.payload();

            if payload.len() < 8 {
                eprintln!("Unexpected TCP Timestamp option size");
                return;
            }
            let ts_val_bytes: [u8; 4] = payload[0..4].try_into().unwrap();
            let ts_ecr_bytes: [u8; 4] = payload[4..8].try_into().unwrap();

            let ts_val = u32::from_be_bytes(ts_val_bytes);
            let ts_ecr = u32::from_be_bytes(ts_ecr_bytes);

            ts_val as u64 + ts_ecr as u64
        } else if (flags & TcpFlags::RST) != 0 {
            // It is expected that RST packets don't contain timestamps.
            // We can't reliably differentiate these from each other.
            // Ignore them.
            return;
        } else {
            eprintln!(
                "TCP {}->{} {}: ignore packet with no timestamp: {:?}",
                packet.get_source(),
                packet.get_destination(),
                ts,
                (packet_seq, packet_ack, "?")
            );
            return;
        };

        let key: TcpKey = (packet_seq, packet_ack, flags, ts_sum);

        if self.seqs.contains_key(&key) {
            eprintln!(
                "TCP {}->{} {}: key {:?} duplicate",
                packet.get_source(),
                packet.get_destination(),
                ts,
                key
            );
            return;
        }
        self.seqs.insert(key, PacketData { ts, size });
    }

    fn get_packets(&self) -> &HashMap<Self::Key, PacketData> {
        &self.seqs
    }

    fn match_with_rcvr(
        &self,
        rcvr: &dyn FlowParser<Packet = Self::Packet, Key = Self::Key>,
    ) -> Vec<SeqResult> {
        let mut result: Vec<SeqResult> = Vec::new();

        let rcvd = rcvr.get_packets();
        let mut rcvd_match_count = 0;

        // Sort sent packets by sent_ts and sequence number. Also sorting by sequence number
        // is important to get a stable order (and packet IDs) during multiple runs.
        let sent = self
            .get_packets()
            .iter()
            .sorted_by_key(|((seq, _, _, _), PacketData { ts, .. })| (ts, seq));
        for (i, (key, sent_packet)) in sent.enumerate() {
            let mut res = SeqResult {
                ts_sent: sent_packet.ts,
                ts_rcvd: None,
                seq: i as u64,
                owd_ms: None,
                size: sent_packet.size,
                lost: true,
            };
            if let Some(rcvd_packet) = rcvd.get(key) {
                res.ts_rcvd = Some(rcvd_packet.ts);
                let owd = rcvd_packet.ts - res.ts_sent;
                res.owd_ms = Some(owd.total(jiff::Unit::Millisecond).unwrap());
                res.lost = false;
                rcvd_match_count += 1;
            };
            result.push(res);
        }

        // Check that we haven't recorded any spurious received packets that have never been sent (according to our parsing logic).
        if rcvd_match_count != rcvd.len() {
            eprintln!(
                "TCP ERROR: found {} received packets, but only matched {} packets",
                rcvd.len(),
                rcvd_match_count
            );
        }

        result
    }
}
