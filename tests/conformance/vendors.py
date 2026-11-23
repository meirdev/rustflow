"""Cases from exporters seen in the field: how a vendor or model departs
from the common reading of a specification, rebuilt with documentation
addresses.

What these exporters get wrong is mostly in the conversion, such as which
sampling rate applies to a record, so their flows matter as much as their
packets.
"""

from netflow_v9 import (
    SYSTEM,
    data,
    options_data,
    options_template,
    options_templates,
    packet,
    template,
    templates,
)
from values import IP, STR, U
from wire import Case, case

EXPORTER = "192.0.2.1"


def system_sampler_in_another_source_id() -> Case:
    flows = [(8, 4), (12, 4), (1, 8), (2, 8), (4, 1)]
    flow_names = [
        "sourceIPv4Address",
        "destinationIPv4Address",
        "octetDeltaCount",
        "packetDeltaCount",
        "protocolIdentifier",
    ]
    sampler = [(48, 4), (84, 40), (49, 1), (50, 2)]
    sampler_names = ["system", "samplerId", "samplerName", "samplerMode", "samplerRandomInterval"]

    def flow(src: str) -> list:
        return [IP(src), IP("198.51.100.10"), U(1500, 8), U(1, 8), U(6, 1)]

    first, second, options = 0x0100_0001, 0x0100_0002, 3
    return case(
        "system_sampler_in_another_source_id",
        "RFC 3954 sections 6.1 and 8",
        "The data comes under source IDs 0x01000001 and 0x01000002, with "
        "no sampler field; the sampling rate only in a System-scoped "
        "options record under source ID 3, every few seconds, naming "
        "sampler 2 in a 4-byte samplerId (1 byte in the registry) and its "
        "interval in 2 bytes, with a NUL-padded samplerName and no FlowSet "
        "padding; each source ID numbers its packets on its own. A System "
        "scope covers the whole exporter, so the rate applies to every "
        "source ID that states none of its own, from the options record on.",
        [
            packet(
                3,
                [templates(template(256, flows)), data(256, flow_names, [flow("192.0.2.10"), flow("192.0.2.11")])],
                sequence_number=5146,
                source_id=first,
                src=EXPORTER,
            ),
            packet(
                2,
                [
                    options_templates(options_template(257, [(SYSTEM, 4)], sampler)),
                    options_data(
                        257,
                        sampler_names,
                        [[U(0xC000_0201, 4), U(2, 4), STR("NETFLOW_SAMPLER", 40), U(2, 1), U(100, 2)]],
                    ),
                ],
                sequence_number=40402,
                source_id=options,
                src=EXPORTER,
            ),
            packet(
                2,
                [templates(template(256, flows)), data(256, flow_names, [flow("192.0.2.12")])],
                sequence_number=7299,
                source_id=second,
                src=EXPORTER,
            ),
            packet(1, [data(256, flow_names, [flow("192.0.2.13")])], sequence_number=5147, source_id=first, src=EXPORTER),
        ],
    )


def cases() -> list[Case]:
    return [system_sampler_in_another_source_id()]
