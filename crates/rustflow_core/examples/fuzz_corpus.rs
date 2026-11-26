//! Writes the seed corpus of the fuzz targets from the test captures:
//!
//! ```sh
//! cargo run -p rustflow_core --features pcap --example fuzz_corpus
//! ```
//!
//! Each capture becomes one `netflow` or `sflow` input and is copied as a
//! `pcap` input. See `fuzz/README.md`.

use std::path::{Path, PathBuf};
use std::{fs, io};

use rustflow_core::reader::{PcapSource, Recv, Source};

fn captures(directory: &Path, found: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            captures(&path, found)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "pcap")
        {
            found.push(path);
        }
    }
    Ok(())
}

fn datagrams(capture: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut source = PcapSource::open(capture)?;
    let mut datagrams = Vec::new();
    while let Recv::Datagram(datagram) = source.recv()? {
        datagrams.push(datagram.payload.to_vec());
    }
    Ok(datagrams)
}

fn main() -> io::Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let corpus = repository.join("fuzz/corpus");
    // The round-trip targets take the inputs of the targets they follow.
    let netflow = ["netflow", "roundtrip_netflow"];
    let sflow = ["sflow", "roundtrip_sflow"];
    for target in netflow.iter().chain(&sflow).chain(&["pcap"]) {
        fs::create_dir_all(corpus.join(target))?;
    }

    let mut found = Vec::new();
    captures(&repository.join("tests/fixtures"), &mut found)?;
    for capture in &found {
        let fixtures = repository.join("tests/fixtures");
        let relative = capture.strip_prefix(&fixtures).expect("found under it");
        let name = relative
            .with_extension("")
            .display()
            .to_string()
            .replace('/', "_");
        fs::copy(capture, corpus.join("pcap").join(&name))?;

        let datagrams = datagrams(capture)?;
        if name.contains("sflow") {
            for (index, datagram) in datagrams.iter().enumerate() {
                for target in sflow {
                    let input = corpus.join(target).join(format!("{name}_{index}"));
                    fs::write(input, datagram)?;
                }
            }
        } else {
            // The `netflow` target reads datagrams, each after its length.
            let mut input = Vec::new();
            for datagram in &datagrams {
                let length = u16::try_from(datagram.len()).expect("a UDP payload");
                input.extend(length.to_be_bytes());
                input.extend(datagram);
            }
            for target in netflow {
                fs::write(corpus.join(target).join(&name), &input)?;
            }
        }
    }
    println!("{} captures into {}", found.len(), corpus.display());
    Ok(())
}
