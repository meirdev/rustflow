//! IPFIX parser tests: wire octets in, rendered records out.
//!
//! Every case is a byte vector and the string the parser should produce from
//! it. Inputs are hex rather than built by helpers so that a case says exactly
//! what is on the wire -- the RFC 7011 vectors are transcribed from the byte
//! diagrams in Appendix A, and malformed inputs (bad lengths, padding,
//! truncation) are just different octets rather than special machinery.
//!
//! The rendering is `sets=<id>/<length>,... rest=<unconsumed> [name=value ...]`
//! per data record, or `Err`. It covers the three things that can silently go
//! wrong: which Sets were recognised, whether the whole Message was consumed,
//! and how each field resolved through the IE registry.
//!
//! Where the parser departs from the RFC the case still records what it
//! actually does, with the divergence named in the comment. A test that lies
//! about current behaviour is worse than no test; a test that documents a bug
//! is how the bug stays visible.

use std::time::Duration;

use hex_literal::hex;
use rustflow_core::common::ie_registry::IERegistry;
use rustflow_core::ipfix::parser::{IpfixParser, Record};

struct Case {
    name: &'static str,
    /// Messages fed to one parser in order; the last one's outcome is asserted.
    /// More than one is needed only when Template state must be built up first.
    msgs: &'static [&'static [u8]],
    want: &'static str,
}

#[rustfmt::skip]
const CASES: &[Case] = &[

    // -- RFC 7011 Appendix A ------------------------------------------------

    Case {
        // A.2.1 Template Set (Length 28) and A.3 Data Set (Length 64).
        name: "A.2.1/A.3 template and three flow records",
        msgs: &[&hex!(
            "000a 006c 0000 0000 0000 0000 0000 0001 0002 001c 0100 0005 0008 0004"
            "000c 0004 000f 0004 0002 0004 0001 0004 0100 0040 c000 020c c000 02fe"
            "c000 0201 0000 1391 0051 8c81 c000 021b c000 0217 c000 0202 0000 02ec"
            "0005 ef46 c000 0238 c000 0241 c000 0203 0000 0005 0000 1986"
        )],
        want: "sets=2/28,256/64 rest=0 \
               [sourceIPv4Address=192.0.2.12 destinationIPv4Address=192.0.2.254 ipNextHopIPv4Address=192.0.2.1 packetDeltaCount=5009 octetDeltaCount=5344385] \
               [sourceIPv4Address=192.0.2.27 destinationIPv4Address=192.0.2.23 ipNextHopIPv4Address=192.0.2.2 packetDeltaCount=748 octetDeltaCount=388934] \
               [sourceIPv4Address=192.0.2.56 destinationIPv4Address=192.0.2.65 ipNextHopIPv4Address=192.0.2.3 packetDeltaCount=5 octetDeltaCount=6534]",
    },

    Case {
        // A.2.2 Template Set (Length 32): field 3 has the enterprise bit set.
        // Enterprise id 15 is a different element from IANA's 15, so the
        // registry misses and the field keeps its numeric name and raw octets.
        name: "A.2.2 enterprise-specific information element",
        msgs: &[&hex!(
            "000a 0048 0000 0000 0000 0000 0000 0001 0002 0020 0101 0005 0008 0004"
            "000c 0004 800f 0004 0000 2b67 0002 0004 0001 0004 0101 0018 c000 020c"
            "c000 02fe aabb ccdd 0000 1391 0051 8c81"
        )],
        want: "sets=2/32,257/24 rest=0 \
               [sourceIPv4Address=192.0.2.12 destinationIPv4Address=192.0.2.254 15=aabbccdd packetDeltaCount=5009 octetDeltaCount=5344385]",
    },

    Case {
        // A.4.1 Options Template Set (Length 24, including two padding octets
        // that must not read as a second record) and its Data Set.
        // Scope fields bypass the registry: numeric name, read as unsigned.
        name: "A.4.1 options template with scope field and padding",
        msgs: &[&hex!(
            "000a 003c 0000 0000 0000 0000 0000 0001 0003 0018 0102 0003 0001 008d"
            "0004 0029 0002 002a 0002 0000 0102 0014 0000 0001 0159 27d9 0000 0002"
            "02b2 4fb2"
        )],
        want: "sets=3/24,258/20 rest=0 \
               [141=1 exportedMessageTotalCount=345 exportedFlowRecordTotalCount=10201] \
               [141=2 exportedMessageTotalCount=690 exportedFlowRecordTotalCount=20402]",
    },

    Case {
        // A.4.3 Options Template with an enterprise-specific scope (Length 28)
        // and A.4.4 its Data Set (Length 20).
        name: "A.4.3/A.4.4 enterprise-specific scope",
        msgs: &[&hex!(
            "000a 0040 0000 0000 0000 0000 0000 0001 0003 001c 0104 0003 0001 807b"
            "0004 0000 2b67 0029 0002 002a 0002 0000 0104 0014 0000 0001 0159 27d9"
            "0000 0002 02b2 4fb2"
        )],
        want: "sets=3/28,260/20 rest=0 \
               [123=1 exportedMessageTotalCount=345 exportedFlowRecordTotalCount=10201] \
               [123=2 exportedMessageTotalCount=690 exportedFlowRecordTotalCount=20402]",
    },

    Case {
        // A.5.1 one length octet ("05" HELLO), then A.5.2's 3-octet escape
        // ("ff 0003" BYE). Figure S gives the escaped length as 0..65535, so it
        // is legal for a short value and there is no need for a 1000-octet
        // vector to reach the branch.
        name: "A.5.1/A.5.2 variable-length encodings",
        msgs: &[&hex!(
            "000a 0030 0000 0000 0000 0000 0000 0001 0002 0010 0100 0002 0060 ffff"
            "0060 ffff 0100 0010 0548 454c 4c4f ff00 0342 5945"
        )],
        want: "sets=2/16,256/16 rest=0 [applicationName=HELLO applicationName=BYE]",
    },

    Case {
        // The complete Message pictured at the head of Appendix A: Template
        // Set, Data Set, Options Template Set, Options Data Set -- 152 octets,
        // matching the Length in A.1. A Data Set may use a Template that
        // arrived earlier in the same Message.
        name: "A.1 complete 152-octet message",
        msgs: &[&hex!(
            "000a 0098 0000 0000 0000 0000 0000 0001 0002 001c 0100 0005 0008 0004"
            "000c 0004 000f 0004 0002 0004 0001 0004 0100 0040 c000 020c c000 02fe"
            "c000 0201 0000 1391 0051 8c81 c000 021b c000 0217 c000 0202 0000 02ec"
            "0005 ef46 c000 0238 c000 0241 c000 0203 0000 0005 0000 1986 0003 0018"
            "0102 0003 0001 008d 0004 0029 0002 002a 0002 0000 0102 0014 0000 0001"
            "0159 27d9 0000 0002 02b2 4fb2"
        )],
        want: "sets=2/28,256/64,3/24,258/20 rest=0 \
               [sourceIPv4Address=192.0.2.12 destinationIPv4Address=192.0.2.254 ipNextHopIPv4Address=192.0.2.1 packetDeltaCount=5009 octetDeltaCount=5344385] \
               [sourceIPv4Address=192.0.2.27 destinationIPv4Address=192.0.2.23 ipNextHopIPv4Address=192.0.2.2 packetDeltaCount=748 octetDeltaCount=388934] \
               [sourceIPv4Address=192.0.2.56 destinationIPv4Address=192.0.2.65 ipNextHopIPv4Address=192.0.2.3 packetDeltaCount=5 octetDeltaCount=6534] \
               [141=1 exportedMessageTotalCount=345 exportedFlowRecordTotalCount=10201] \
               [141=2 exportedMessageTotalCount=690 exportedFlowRecordTotalCount=20402]",
    },

    // -- Message header -----------------------------------------------------

    Case {
        // Section 3.1 fixes the Version at 0x000a. It is verified, as in the
        // NetFlow v5 and v9 parsers, so a datagram of another version is
        // rejected here rather than being decoded as IPFIX.
        name: "a non-IPFIX version is rejected",
        msgs: &[&hex!("0009 001c 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004")],
        want: "Err",
    },

    Case {
        // A Length below the 16-octet header saturates to an empty body: no
        // Sets, and the body comes back unconsumed rather than panicking.
        name: "header length below the header size",
        msgs: &[&hex!("000a 0008 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004")],
        want: "sets= rest=12",
    },

    Case {
        name: "header length beyond the datagram",
        msgs: &[&hex!("000a 03e8 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004")],
        want: "Err",
    },

    Case {
        name: "truncated header",
        msgs: &[&hex!("000a 0010 0000")],
        want: "Err",
    },

    Case {
        // Octets past the declared Length are left in the remainder, which is
        // how a caller detects a malformed datagram.
        name: "trailing octets past the declared length",
        msgs: &[&hex!(
            "000a 001c 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004"
            "dead beef"
        )],
        want: "sets=2/12 rest=4",
    },

    // -- Sets ---------------------------------------------------------------

    Case {
        // A Data Set whose Template never arrived is reported with no records
        // and parsing continues into the next Set: one missing Template must
        // not cost the rest of the Message.
        name: "unknown template does not stop the message",
        msgs: &[
            &hex!("000a 001c 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004"),
            &hex!(
                "000a 0024 0000 0000 0000 0000 0000 0001 03e7 000c 0000 0000 0000 0000"
                "0100 0008 0000 0007"
            ),
        ],
        want: "sets=999/12,256/8 rest=0 [octetDeltaCount=7]",
    },

    Case {
        // Set IDs 4..=255 are reserved (section 3.3.2). Skipping one must
        // still consume it, or the enclosing many0 would spin on it forever.
        name: "reserved set id is skipped without looping",
        msgs: &[&hex!(
            "000a 0028 0000 0000 0000 0000 0000 0001 0004 000c aaaa aaaa aaaa aaaa"
            "0002 000c 0100 0001 0001 0004"
        )],
        want: "sets=4/12,2/12 rest=0",
    },

    // -- Padding versus truncation (section 3.3.1) --------------------------

    Case {
        // Padding shorter than a record is ignored, because too few octets
        // remain for another record.
        name: "padding shorter than a record is ignored",
        msgs: &[&hex!(
            "000a 0027 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004"
            "0100 000b 0000 0007 0000 00"
        )],
        want: "sets=2/12,256/11 rest=0 [octetDeltaCount=7]",
    },

    Case {
        // Section 3.3.1 requires padding to be shorter than a record precisely
        // because the parser cannot tell them apart. With a 1-octet record,
        // three padding octets become three phantom zero records.
        name: "padding as long as a record becomes phantom records",
        msgs: &[&hex!(
            "000a 0024 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0001"
            "0100 0008 0600 0000"
        )],
        want: "sets=2/12,256/8 rest=0 [octetDeltaCount=6] [octetDeltaCount=0] [octetDeltaCount=0] [octetDeltaCount=0]",
    },

    // -- Field values -------------------------------------------------------

    Case {
        // DIVERGENCE. Section 6.2 allows an unsigned element to be exported
        // in fewer octets and requires it to decode as that same integer.
        // Only widths 1, 2, 4 and 8 are implemented; 3 (and 5, 6, 7) fall
        // through to the octet-array arm, so the counter arrives as opaque
        // hex. Should be octetDeltaCount=66051.
        name: "reduced-size encoding decodes as octets, not an integer",
        msgs: &[&hex!(
            "000a 0023 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0003"
            "0100 0007 0102 03"
        )],
        want: "sets=2/12,256/7 rest=0 [octetDeltaCount=010203]",
    },

    Case {
        // A string field that is not valid UTF-8 fails the whole record, and
        // because the record loop stops at the first failure the well-formed
        // record after it is lost too.
        name: "invalid utf-8 drops its record and every record after it",
        msgs: &[&hex!(
            "000a 0034 0000 0000 0000 0000 0000 0001 0002 0010 0100 0002 0060 0004"
            "0001 0004 0100 0014 fffe fdfc 0000 0007 6f6b 6179 0000 0009"
        )],
        want: "sets=2/16,256/20 rest=0",
    },

    Case {
        // A record made only of zero-length fields consumes nothing. The
        // record loop errors on the non-advancing parser, that error stops the
        // outer loop over Sets, and because the body was taken by length the
        // Message still reports as fully consumed -- so every Set is discarded
        // with no signal at all, including the well-formed one that follows.
        name: "zero-length-only template silently discards every set",
        msgs: &[
            &hex!(
                "000a 0028 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0000"
                "0002 000c 0101 0001 0001 0004"
            ),
            &hex!(
                "000a 001e 0000 0000 0000 0000 0000 0001 0100 0006 aabb 0101 0008 0000"
                "0007"
            ),
        ],
        want: "sets= rest=0",
    },

    Case {
        // NTP timestamps run from 1900, so an all-zero dateTimeMicroseconds is
        // the NTP epoch rather than an error or a null.
        name: "all-zero ntp timestamp is 1900, not an error",
        msgs: &[&hex!(
            "000a 0028 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 009a 0008"
            "0100 000c 0000 0000 0000 0000"
        )],
        want: "sets=2/12,256/12 rest=0 [flowStartMicroseconds=1900-01-01T00:00:00.000000]",
    },

    Case {
        // dateTimeMilliseconds is read as a signed millisecond count, so a
        // value with the top bit set is out of range and fails the record.
        name: "out-of-range millisecond timestamp drops the record",
        msgs: &[&hex!(
            "000a 0030 0000 0000 0000 0000 0000 0001 0002 0010 0100 0002 0098 0008"
            "0001 0004 0100 0010 8000 0000 0000 0000 0000 0007"
        )],
        want: "sets=2/16,256/16 rest=0",
    },

    Case {
        // Section 6.1.5: 1 is true, 2 is false. Anything else fails the record
        // rather than being coerced.
        name: "boolean outside 1 and 2 drops the record",
        msgs: &[&hex!(
            "000a 0021 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0114 0001"
            "0100 0005 03"
        )],
        want: "sets=2/12,256/5 rest=0",
    },

    // -- Template cache -----------------------------------------------------

    Case {
        // Section 8 allows a Template ID to be reused for a different
        // Template. The cached entry must be replaced, or later records decode
        // against the old field list -- producing plausible, wrong data.
        name: "redefining a template replaces the cached fields",
        msgs: &[
            &hex!(
                "000a 0020 0000 0000 0000 0000 0000 0001 0002 0010 0100 0002 0004 0001"
                "0007 0002"
            ),
            &hex!(
                "000a 0027 0000 0000 0000 0000 0000 0001 0002 0010 0100 0002 000b 0002"
                "0005 0001 0100 0007 01bb 01"
            ),
        ],
        want: "sets=2/16,256/7 rest=0 [destinationTransportPort=443 ipClassOfService=1]",
    },

    Case {
        // Template IDs are scoped to the Observation Domain (section 3.4.1):
        // id 256 in domain 1 and in domain 2 are different Templates.
        name: "templates are scoped per observation domain",
        msgs: &[
            &hex!("000a 001c 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0004 0001"),
            &hex!("000a 001c 0000 0000 0000 0000 0000 0002 0002 000c 0100 0001 0005 0001"),
            &hex!("000a 0015 0000 0000 0000 0000 0000 0001 0100 0005 06"),
        ],
        want: "sets=256/5 rest=0 [protocolIdentifier=6]",
    },
];

fn parser() -> IpfixParser {
    IpfixParser::new(IERegistry::default(), Duration::from_secs(600))
}

/// Feed each Message to one parser and render the last one's outcome.
fn run(msgs: &[&[u8]]) -> String {
    let mut parser = parser();
    let mut out = String::from("Err");

    for msg in msgs {
        out = match parser.parse(msg) {
            Err(_) => "Err".to_string(),
            Ok((rest, packet)) => {
                let sets: Vec<_> = packet
                    .sets
                    .iter()
                    .map(|s| format!("{}/{}", s.id, s.length))
                    .collect();

                let records: Vec<_> = packet
                    .sets
                    .iter()
                    .flat_map(|s| &s.records)
                    .filter_map(|r| match r {
                        Record::Data(d) | Record::OptionsData(d) => Some(d),
                        _ => None,
                    })
                    .map(|d| {
                        let fields: Vec<_> =
                            d.0.iter()
                                .map(|(_, name, value)| format!("{name}={value}"))
                                .collect();
                        format!("[{}]", fields.join(" "))
                    })
                    .collect();

                format!(
                    "sets={} rest={} {}",
                    sets.join(","),
                    rest.len(),
                    records.join(" ")
                )
                .trim_end()
                .to_string()
            }
        };
    }

    out
}

#[test]
fn cases() {
    let failures: Vec<_> = CASES
        .iter()
        .filter_map(|c| {
            let got = run(c.msgs);
            (got != c.want).then(|| format!("{}\n  want: {}\n   got: {}", c.name, c.want, got))
        })
        .collect();

    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n\n{}\n",
        failures.len(),
        CASES.len(),
        failures.join("\n\n")
    );
}

/// Keep the table's compact rendered assertions, but also verify protocol
/// metadata that is intentionally absent from that rendering.
#[test]
fn rfc_7011_appendix_a_header_and_template_are_parsed() {
    let message = CASES[5].msgs[0];
    let (rest, packet) = parser().parse(message).expect("parse Appendix A message");

    assert!(rest.is_empty());
    assert_eq!(packet.header.version, 10);
    assert_eq!(packet.header.length, 152);
    assert_eq!(packet.header.export_time.timestamp(), 0);
    assert_eq!(packet.header.sequence_number, 0);
    assert_eq!(packet.header.observation_domain_id, 1);

    assert_eq!(packet.sets.len(), 4);
    assert_eq!(packet.sets[0].id, 2);
    assert_eq!(packet.sets[0].length, 28);

    let Record::Template(template) = &packet.sets[0].records[0] else {
        panic!("first record must be the Appendix A Template Record");
    };
    assert_eq!(template.template_id, 256);
    assert_eq!(template.field_count, 5);
    assert_eq!(
        template
            .fields
            .iter()
            .map(|field| (field.information_element_identifier, field.field_length))
            .collect::<Vec<_>>(),
        [(8, 4), (12, 4), (15, 4), (2, 4), (1, 4)]
    );
}

/// No prefix of a valid Message may panic. Truncation is the ordinary case in
/// production -- a datagram clipped by an MTU, an Exporter restarted mid-write
/// -- and the length arithmetic that handles it is exactly what a performance
/// rewrite touches.
#[test]
fn no_truncation_panics() {
    let full = CASES[5].msgs[0];

    for len in 0..=full.len() {
        let _ = parser().parse(&full[..len]);
    }
}

/// Templates are held with a timeout; once it lapses their Data Sets stop
/// decoding, exactly as if the Template had never arrived. The timeout is read
/// from `Instant::now()` with no injectable clock, so this has to sleep.
#[test]
fn templates_expire() {
    let template = &hex!("000a 001c 0000 0000 0000 0000 0000 0001 0002 000c 0100 0001 0001 0004");
    let data = &hex!("000a 0018 0000 0000 0000 0000 0000 0001 0100 0008 0000 0007");

    let mut parser = IpfixParser::new(IERegistry::default(), Duration::from_millis(50));
    parser.parse(template).expect("install template");

    let (_, packet) = parser.parse(data).expect("parse");
    assert_eq!(packet.sets[0].records.len(), 1, "decodes while live");

    std::thread::sleep(Duration::from_millis(80));

    let (_, packet) = parser.parse(data).expect("parse");
    assert!(
        packet.sets[0].records.is_empty(),
        "expired template still decoded"
    );
}
