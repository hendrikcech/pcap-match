# pcap-match
Use packet captures from sender and receiver to calculate the one-way delay (OWD) of packets.

## Build
cargo can also build libpcap if invoked with the feature `static`. Without it, libpcap already needs to be available on the system.
```
git clone https://github.com/hendrikcech/pcap-match.git  
cd pcap-match
git submodule update --init # optional: fetches libpcap
cargo build --release -F static # `-F static` is optional
```