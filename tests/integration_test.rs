use std::{
    fmt::Debug,
    fs::{self, File},
    io::Read,
    path::Path,
    process::ExitCode,
};

use clap::Parser;
use pcap_match::{cli::Args, run_args};

#[test]
fn test_iperf3_udp() {
    let input = vec![
        "pcap-match",
        "--name",
        "iperf3_udp_test",
        "--iperf3-udp-dst",
        "5201",
        "./tests/iperf3_udp_client.pcap",
        "./tests/iperf3_udp_server.pcap",
    ];

    run_and_compare(
        input,
        "./tests/iperf3_udp.5201.csv",
        "./tests/iperf3_udp_test.5201.csv",
    );
}

#[test]
fn test_iperf3_tcp_ipv6() {
    let input = vec![
        "pcap-match",
        "--name",
        "iperf3_tcp_ipv6_test",
        "--tcp-dst",
        "5201",
        "./tests/iperf3_tcp_ipv6_client.pcap",
        "./tests/iperf3_tcp_ipv6_server.pcap",
    ];

    run_and_compare(
        input,
        "./tests/iperf3_tcp_ipv6.5201.csv",
        "./tests/iperf3_tcp_ipv6_test.5201.csv",
    );
}

#[test]
fn test_iperf3_tcp_ipv4() {
    let input = vec![
        "pcap-match",
        "--name",
        "iperf3_tcp_ipv4_test",
        "--tcp-dst",
        "5201",
        "./tests/iperf3_tcp_ipv4_client.pcap",
        "./tests/iperf3_tcp_ipv4_server.pcap",
    ];

    run_and_compare(
        input,
        "./tests/iperf3_tcp_ipv4.5201.csv",
        "./tests/iperf3_tcp_ipv4_test.5201.csv",
    );
}

fn run_and_compare<P: Debug>(input: Vec<&str>, expected: P, observed: P)
where
    P: AsRef<Path>,
{
    let args = Args::parse_from(input);
    assert_eq!(run_args(args), ExitCode::SUCCESS);

    let mut f_expected = File::open(&expected)
        .expect(format!("'Expected' file does not exist: {expected:?}").as_str());
    let mut f_observed = File::open(&observed)
        .expect(format!("New output file does not exist: {observed:?}").as_str());
    assert!(
        diff_files(&mut f_expected, &mut f_observed),
        "resulting file differs"
    );

    // Only deleted if test suceeded
    fs::remove_file(observed).unwrap();
}

/// Takes two file arguments and returns true if the two files are identical.
pub fn diff_files(a: &mut File, b: &mut File) -> bool {
    let buf_a = &mut [0; 1024];
    let buf_b = &mut [0; 1024];
    loop {
        match a.read(buf_a) {
            Err(_) => return false,
            Ok(f1_read_len) => match b.read(buf_b) {
                Err(_) => return false,
                Ok(f2_read_len) => {
                    if f1_read_len != f2_read_len {
                        return false;
                    }
                    if f1_read_len == 0 {
                        return true;
                    }
                    if &buf_a[0..f1_read_len] != &buf_b[0..f2_read_len] {
                        return false;
                    }
                }
            },
        }
    }
}
