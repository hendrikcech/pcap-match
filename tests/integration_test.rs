use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::ExitCode,
};

use clap::Parser;
use pcap_match::{cli::Args, run_args};

#[test]
fn test_help() {
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

fn run_and_compare<P>(input: Vec<&str>, a_path: P, b_path: P)
where
    P: AsRef<Path>,
{
    let args = Args::parse_from(input);
    assert_eq!(run_args(args), ExitCode::SUCCESS);

    let mut a = File::open(a_path).unwrap();
    let mut b = File::open(&b_path).unwrap();
    assert!(diff_files(&mut a, &mut b), "resulting file differs");

    fs::remove_file(b_path).unwrap();
}

/// Takes two file arguments and returns true if the two files are identical.
pub fn diff_files(f1: &mut File, f2: &mut File) -> bool {
    let buff1: &mut [u8] = &mut [0; 1024];
    let buff2: &mut [u8] = &mut [0; 1024];
    loop {
        match f1.read(buff1) {
            Err(_) => return false,
            Ok(f1_read_len) => match f2.read(buff2) {
                Err(_) => return false,
                Ok(f2_read_len) => {
                    if f1_read_len != f2_read_len {
                        return false;
                    }
                    if f1_read_len == 0 {
                        return true;
                    }
                    if &buff1[0..f1_read_len] != &buff2[0..f2_read_len] {
                        return false;
                    }
                }
            },
        }
    }
}
