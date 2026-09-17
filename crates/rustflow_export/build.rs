fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_STATIC");
    // The `pcap` crate links libpcap dynamically. With LIBPCAP_STATIC set
    // and a libpcap.a in LIBPCAP_LIBDIR, link it into the binary instead
    // (for the static musl release). Windows links wpcap, not libpcap.
    if std::env::var_os("CARGO_FEATURE_PCAP").is_some()
        && std::env::var_os("LIBPCAP_STATIC").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
    {
        println!("cargo:rustc-link-lib=static=pcap");
    }
}
