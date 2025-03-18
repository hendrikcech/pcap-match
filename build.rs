fn main() {
    #[cfg(all(unix, feature = "static"))]
    {
        let linux_kernel_headers = std::env::var("LINUX_KERNEL_HEADERS").ok();

        let mut cmake_config = cmake::Config::new("libpcap");

        if let Some(linux_kernel_headers) = linux_kernel_headers {
            cmake_config.define("DISABLE_USB", "ON");
            cmake_config.define("DISABLE_DBUS", "ON");
            cmake_config.define("DISABLE_BLUETOOTH", "ON");
            cmake_config.define("DISABLE_RDMA", "ON");
            cmake_config.define("ENABLE_REMOTE", "OFF");
            cmake_config.define("USE_STATIC_RT", "ON");
            cmake_config.define("BUILD_SHARED_LIBS", "OFF");
            cmake_config.cflag(format!("-I{}", linux_kernel_headers));
        }

        // Disable DPDK due to unresolved bug
        // https://github.com/the-tcpdump-group/libpcap/issues/1159
        cmake_config.define("DISABLE_DPDK", "ON");

        let mut dst = cmake_config.build();
        dst.push("lib");

        println!("cargo:rustc-link-search=native={}", dst.display());
        println!("cargo:rustc-link-lib=static=pcap");
    }
}