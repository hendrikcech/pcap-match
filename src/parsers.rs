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
            res.owd_ms = Some(owd.as_millis_f64());
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
    order: Vec<TcpKey>,
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
        self.order.push(key);
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

        for (i, key) in self.order.iter().enumerate() {
            let sent_packet = &self.seqs[key];
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
                res.owd_ms = Some(owd.as_millis_f64());
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

#[cfg(test)]
mod tests {
    use pnet::packet::tcp::{TcpFlags, TcpPacket};

    use super::{FlowParser, Iperf3TcpParser, PacketData, hashmap_match_u64};

    #[test]
    fn matching_preserves_fractional_and_negative_delays() {
        let sent = jiff::Timestamp::new(1, 0).unwrap();
        for (nanos, expected) in [(1_250_000, 1.25), (-1_250_000, -1.25)] {
            let received = jiff::Timestamp::new(1, nanos).unwrap();
            let sender = [(1, PacketData { ts: sent, size: 1 })].into();
            let receiver = [(
                1,
                PacketData {
                    ts: received,
                    size: 1,
                },
            )]
            .into();
            assert_eq!(
                hashmap_match_u64(&sender, &receiver)[0].owd_ms,
                Some(expected)
            );

            let mut sender = Iperf3TcpParser::default();
            let mut receiver = Iperf3TcpParser::default();
            let bytes = tcp_packet(1);
            let packet = TcpPacket::new(&bytes).unwrap();
            sender.parse(sent, 1, &packet);
            receiver.parse(received, 1, &packet);
            assert_eq!(sender.match_with_rcvr(&receiver)[0].owd_ms, Some(expected));
        }
    }

    fn tcp_packet(seq: u32) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0..2].copy_from_slice(&12345u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&5201u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&seq.to_be_bytes());
        bytes[8..12].copy_from_slice(&7u32.to_be_bytes());
        bytes[12] = 8 << 4;
        bytes[13] = TcpFlags::ACK;
        bytes[14..16].copy_from_slice(&4096u16.to_be_bytes());
        bytes[20] = 8;
        bytes[21] = 10;
        bytes[22..26].copy_from_slice(&1u32.to_be_bytes());
        bytes[26..30].copy_from_slice(&2u32.to_be_bytes());
        bytes
    }

    fn parse(parser: &mut Iperf3TcpParser, seq: u32, seconds: i64, size: u16) {
        let bytes = tcp_packet(seq);
        let packet = TcpPacket::new(&bytes).unwrap();
        parser.parse(jiff::Timestamp::new(seconds, 0).unwrap(), size, &packet);
    }

    #[test]
    fn tcp_matching_preserves_sender_record_order() {
        let sender_packets = [
            (4_294_964_875, 1),
            (4_294_966_323, 1),
            (475, 1),
            (1923, 0),
            (3371, 1),
        ];
        let mut sender = Iperf3TcpParser::default();
        for (i, (seq, seconds)) in sender_packets.into_iter().enumerate() {
            parse(&mut sender, seq, seconds, 1000 + i as u16);
        }
        // A duplicate is excluded and must not create another ordered row.
        parse(&mut sender, sender_packets[0].0, 99, 2000);

        let receiver_order = [0, 2, 1, 4, 3];
        let mut receiver = Iperf3TcpParser::default();
        for (i, sender_index) in receiver_order.into_iter().enumerate() {
            parse(
                &mut receiver,
                sender_packets[sender_index].0,
                10 + i as i64,
                1000,
            );
        }

        let matched = sender.match_with_rcvr(&receiver);
        assert_eq!(matched.len(), sender_packets.len());
        assert_eq!(
            matched.iter().map(|row| row.seq).collect::<Vec<_>>(),
            (0..sender_packets.len() as u64).collect::<Vec<_>>()
        );
        assert_eq!(
            matched.iter().map(|row| row.ts_sent).collect::<Vec<_>>(),
            sender_packets
                .iter()
                .map(|(_, seconds)| jiff::Timestamp::new(*seconds, 0).unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            matched.iter().map(|row| row.ts_rcvd).collect::<Vec<_>>(),
            [10, 12, 11, 14, 13].map(|seconds| Some(jiff::Timestamp::new(seconds, 0).unwrap()))
        );
        assert_eq!(
            matched.iter().map(|row| row.size).collect::<Vec<_>>(),
            [1000, 1001, 1002, 1003, 1004]
        );
        assert!(matched.iter().all(|row| !row.lost));
    }
}
