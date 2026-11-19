//! IANA-registered IPFIX Information Element IDs.
//!
//! Source: <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use super::DataType::{self, *};
use super::ElementId;
use super::Semantic::{self, *};

#[rustfmt::skip]
pub(crate) const ELEMENTS: &[(u16, &str, DataType, Option<Semantic>)] = &[
    (1, "octetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (2, "packetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (3, "deltaFlowCount", Unsigned64, Some(DeltaCounter)),
    (4, "protocolIdentifier", Unsigned8, Some(Identifier)),
    (5, "ipClassOfService", Unsigned8, Some(Identifier)),
    (6, "tcpControlBits", Unsigned16, Some(Flags)),
    (7, "sourceTransportPort", Unsigned16, Some(Identifier)),
    (8, "sourceIPv4Address", Ipv4Address, Some(Default)),
    (9, "sourceIPv4PrefixLength", Unsigned8, None),
    (10, "ingressInterface", Unsigned32, Some(Identifier)),
    (11, "destinationTransportPort", Unsigned16, Some(Identifier)),
    (12, "destinationIPv4Address", Ipv4Address, Some(Default)),
    (13, "destinationIPv4PrefixLength", Unsigned8, None),
    (14, "egressInterface", Unsigned32, Some(Identifier)),
    (15, "ipNextHopIPv4Address", Ipv4Address, Some(Default)),
    (16, "bgpSourceAsNumber", Unsigned32, Some(Identifier)),
    (17, "bgpDestinationAsNumber", Unsigned32, Some(Identifier)),
    (18, "bgpNextHopIPv4Address", Ipv4Address, Some(Default)),
    (19, "postMCastPacketDeltaCount", Unsigned64, Some(DeltaCounter)),
    (20, "postMCastOctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (21, "flowEndSysUpTime", Unsigned32, None),
    (22, "flowStartSysUpTime", Unsigned32, None),
    (23, "postOctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (24, "postPacketDeltaCount", Unsigned64, Some(DeltaCounter)),
    (25, "minimumIpTotalLength", Unsigned64, None),
    (26, "maximumIpTotalLength", Unsigned64, None),
    (27, "sourceIPv6Address", Ipv6Address, Some(Default)),
    (28, "destinationIPv6Address", Ipv6Address, Some(Default)),
    (29, "sourceIPv6PrefixLength", Unsigned8, None),
    (30, "destinationIPv6PrefixLength", Unsigned8, None),
    (31, "flowLabelIPv6", Unsigned32, Some(Identifier)),
    (32, "icmpTypeCodeIPv4", Unsigned16, Some(Identifier)),
    (33, "igmpType", Unsigned8, Some(Identifier)),
    (34, "samplingInterval", Unsigned32, Some(Quantity)),
    (35, "samplingAlgorithm", Unsigned8, Some(Identifier)),
    (36, "flowActiveTimeout", Unsigned16, None),
    (37, "flowIdleTimeout", Unsigned16, None),
    (38, "engineType", Unsigned8, Some(Identifier)),
    (39, "engineId", Unsigned8, Some(Identifier)),
    (40, "exportedOctetTotalCount", Unsigned64, Some(TotalCounter)),
    (41, "exportedMessageTotalCount", Unsigned64, Some(TotalCounter)),
    (42, "exportedFlowRecordTotalCount", Unsigned64, Some(TotalCounter)),
    (43, "ipv4RouterSc", Ipv4Address, Some(Default)),
    (44, "sourceIPv4Prefix", Ipv4Address, Some(Default)),
    (45, "destinationIPv4Prefix", Ipv4Address, Some(Default)),
    (46, "mplsTopLabelType", Unsigned8, Some(Identifier)),
    (47, "mplsTopLabelIPv4Address", Ipv4Address, Some(Default)),
    (48, "samplerId", Unsigned8, Some(Identifier)),
    (49, "samplerMode", Unsigned8, Some(Identifier)),
    (50, "samplerRandomInterval", Unsigned32, Some(Quantity)),
    (51, "classId", Unsigned8, Some(Identifier)),
    (52, "minimumTTL", Unsigned8, None),
    (53, "maximumTTL", Unsigned8, None),
    (54, "fragmentIdentification", Unsigned32, Some(Identifier)),
    (55, "postIpClassOfService", Unsigned8, Some(Identifier)),
    (56, "sourceMacAddress", MacAddress, Some(Default)),
    (57, "postDestinationMacAddress", MacAddress, Some(Default)),
    (58, "vlanId", Unsigned16, Some(Identifier)),
    (59, "postVlanId", Unsigned16, Some(Identifier)),
    (60, "ipVersion", Unsigned8, Some(Identifier)),
    (61, "flowDirection", Unsigned8, Some(Identifier)),
    (62, "ipNextHopIPv6Address", Ipv6Address, Some(Default)),
    (63, "bgpNextHopIPv6Address", Ipv6Address, Some(Default)),
    (64, "ipv6ExtensionHeaders", Unsigned32, Some(Flags)),
    (70, "mplsTopLabelStackSection", OctetArray, Some(Default)),
    (71, "mplsLabelStackSection2", OctetArray, Some(Default)),
    (72, "mplsLabelStackSection3", OctetArray, Some(Default)),
    (73, "mplsLabelStackSection4", OctetArray, Some(Default)),
    (74, "mplsLabelStackSection5", OctetArray, Some(Default)),
    (75, "mplsLabelStackSection6", OctetArray, Some(Default)),
    (76, "mplsLabelStackSection7", OctetArray, Some(Default)),
    (77, "mplsLabelStackSection8", OctetArray, Some(Default)),
    (78, "mplsLabelStackSection9", OctetArray, Some(Default)),
    (79, "mplsLabelStackSection10", OctetArray, Some(Default)),
    (80, "destinationMacAddress", MacAddress, Some(Default)),
    (81, "postSourceMacAddress", MacAddress, Some(Default)),
    (82, "interfaceName", String, Some(Default)),
    (83, "interfaceDescription", String, Some(Default)),
    (84, "samplerName", String, None),
    (85, "octetTotalCount", Unsigned64, Some(TotalCounter)),
    (86, "packetTotalCount", Unsigned64, Some(TotalCounter)),
    (87, "flagsAndSamplerId", Unsigned32, Some(Identifier)),
    (88, "fragmentOffset", Unsigned16, Some(Quantity)),
    (89, "forwardingStatus", Unsigned32, Some(Identifier)),
    (90, "mplsVpnRouteDistinguisher", OctetArray, Some(Default)),
    (91, "mplsTopLabelPrefixLength", Unsigned8, Some(Quantity)),
    (92, "srcTrafficIndex", Unsigned32, Some(Identifier)),
    (93, "dstTrafficIndex", Unsigned32, Some(Identifier)),
    (94, "applicationDescription", String, Some(Default)),
    (95, "applicationId", OctetArray, Some(Default)),
    (96, "applicationName", String, Some(Default)),
    (98, "postIpDiffServCodePoint", Unsigned8, Some(Identifier)),
    (99, "multicastReplicationFactor", Unsigned32, Some(Quantity)),
    (100, "className", String, None),
    (101, "classificationEngineId", Unsigned8, Some(Identifier)),
    (102, "layer2packetSectionOffset", Unsigned16, Some(Quantity)),
    (103, "layer2packetSectionSize", Unsigned16, Some(Quantity)),
    (104, "layer2packetSectionData", OctetArray, None),
    (128, "bgpNextAdjacentAsNumber", Unsigned32, Some(Identifier)),
    (129, "bgpPrevAdjacentAsNumber", Unsigned32, Some(Identifier)),
    (130, "exporterIPv4Address", Ipv4Address, Some(Default)),
    (131, "exporterIPv6Address", Ipv6Address, Some(Default)),
    (132, "droppedOctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (133, "droppedPacketDeltaCount", Unsigned64, Some(DeltaCounter)),
    (134, "droppedOctetTotalCount", Unsigned64, Some(TotalCounter)),
    (135, "droppedPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (136, "flowEndReason", Unsigned8, Some(Identifier)),
    (137, "commonPropertiesId", Unsigned64, Some(Identifier)),
    (138, "observationPointId", Unsigned64, Some(Identifier)),
    (139, "icmpTypeCodeIPv6", Unsigned16, Some(Identifier)),
    (140, "mplsTopLabelIPv6Address", Ipv6Address, Some(Default)),
    (141, "lineCardId", Unsigned32, Some(Identifier)),
    (142, "portId", Unsigned32, Some(Identifier)),
    (143, "meteringProcessId", Unsigned32, Some(Identifier)),
    (144, "exportingProcessId", Unsigned32, Some(Identifier)),
    (145, "templateId", Unsigned16, Some(Identifier)),
    (146, "wlanChannelId", Unsigned8, Some(Identifier)),
    (147, "wlanSSID", String, Some(Default)),
    (148, "flowId", Unsigned64, Some(Identifier)),
    (149, "observationDomainId", Unsigned32, Some(Identifier)),
    (150, "flowStartSeconds", DateTimeSeconds, Some(Default)),
    (151, "flowEndSeconds", DateTimeSeconds, Some(Default)),
    (152, "flowStartMilliseconds", DateTimeMilliseconds, Some(Default)),
    (153, "flowEndMilliseconds", DateTimeMilliseconds, Some(Default)),
    (154, "flowStartMicroseconds", DateTimeMicroseconds, Some(Default)),
    (155, "flowEndMicroseconds", DateTimeMicroseconds, Some(Default)),
    (156, "flowStartNanoseconds", DateTimeNanoseconds, Some(Default)),
    (157, "flowEndNanoseconds", DateTimeNanoseconds, Some(Default)),
    (158, "flowStartDeltaMicroseconds", Unsigned32, None),
    (159, "flowEndDeltaMicroseconds", Unsigned32, None),
    (160, "systemInitTimeMilliseconds", DateTimeMilliseconds, Some(Default)),
    (161, "flowDurationMilliseconds", Unsigned32, None),
    (162, "flowDurationMicroseconds", Unsigned32, None),
    (163, "observedFlowTotalCount", Unsigned64, Some(TotalCounter)),
    (164, "ignoredPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (165, "ignoredOctetTotalCount", Unsigned64, Some(TotalCounter)),
    (166, "notSentFlowTotalCount", Unsigned64, Some(TotalCounter)),
    (167, "notSentPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (168, "notSentOctetTotalCount", Unsigned64, Some(TotalCounter)),
    (169, "destinationIPv6Prefix", Ipv6Address, Some(Default)),
    (170, "sourceIPv6Prefix", Ipv6Address, Some(Default)),
    (171, "postOctetTotalCount", Unsigned64, Some(TotalCounter)),
    (172, "postPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (173, "flowKeyIndicator", Unsigned64, Some(Flags)),
    (174, "postMCastPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (175, "postMCastOctetTotalCount", Unsigned64, Some(TotalCounter)),
    (176, "icmpTypeIPv4", Unsigned8, Some(Identifier)),
    (177, "icmpCodeIPv4", Unsigned8, Some(Identifier)),
    (178, "icmpTypeIPv6", Unsigned8, Some(Identifier)),
    (179, "icmpCodeIPv6", Unsigned8, Some(Identifier)),
    (180, "udpSourcePort", Unsigned16, Some(Identifier)),
    (181, "udpDestinationPort", Unsigned16, Some(Identifier)),
    (182, "tcpSourcePort", Unsigned16, Some(Identifier)),
    (183, "tcpDestinationPort", Unsigned16, Some(Identifier)),
    (184, "tcpSequenceNumber", Unsigned32, None),
    (185, "tcpAcknowledgementNumber", Unsigned32, None),
    (186, "tcpWindowSize", Unsigned16, None),
    (187, "tcpUrgentPointer", Unsigned16, None),
    (188, "tcpHeaderLength", Unsigned8, None),
    (189, "ipHeaderLength", Unsigned8, None),
    (190, "totalLengthIPv4", Unsigned16, None),
    (191, "payloadLengthIPv6", Unsigned16, None),
    (192, "ipTTL", Unsigned8, None),
    (193, "nextHeaderIPv6", Unsigned8, None),
    (194, "mplsPayloadLength", Unsigned32, None),
    (195, "ipDiffServCodePoint", Unsigned8, Some(Identifier)),
    (196, "ipPrecedence", Unsigned8, Some(Identifier)),
    (197, "fragmentFlags", Unsigned8, Some(Flags)),
    (198, "octetDeltaSumOfSquares", Unsigned64, None),
    (199, "octetTotalSumOfSquares", Unsigned64, None),
    (200, "mplsTopLabelTTL", Unsigned8, None),
    (201, "mplsLabelStackLength", Unsigned32, None),
    (202, "mplsLabelStackDepth", Unsigned32, None),
    (203, "mplsTopLabelExp", Unsigned8, Some(Flags)),
    (204, "ipPayloadLength", Unsigned32, None),
    (205, "udpMessageLength", Unsigned16, None),
    (206, "isMulticast", Unsigned8, Some(Flags)),
    (207, "ipv4IHL", Unsigned8, None),
    (208, "ipv4Options", Unsigned32, Some(Flags)),
    (209, "tcpOptions", Unsigned64, Some(Flags)),
    (210, "paddingOctets", OctetArray, Some(Default)),
    (211, "collectorIPv4Address", Ipv4Address, Some(Default)),
    (212, "collectorIPv6Address", Ipv6Address, Some(Default)),
    (213, "exportInterface", Unsigned32, Some(Identifier)),
    (214, "exportProtocolVersion", Unsigned8, Some(Identifier)),
    (215, "exportTransportProtocol", Unsigned8, Some(Identifier)),
    (216, "collectorTransportPort", Unsigned16, Some(Identifier)),
    (217, "exporterTransportPort", Unsigned16, Some(Identifier)),
    (218, "tcpSynTotalCount", Unsigned64, Some(TotalCounter)),
    (219, "tcpFinTotalCount", Unsigned64, Some(TotalCounter)),
    (220, "tcpRstTotalCount", Unsigned64, Some(TotalCounter)),
    (221, "tcpPshTotalCount", Unsigned64, Some(TotalCounter)),
    (222, "tcpAckTotalCount", Unsigned64, Some(TotalCounter)),
    (223, "tcpUrgTotalCount", Unsigned64, Some(TotalCounter)),
    (224, "ipTotalLength", Unsigned64, None),
    (225, "postNATSourceIPv4Address", Ipv4Address, Some(Default)),
    (226, "postNATDestinationIPv4Address", Ipv4Address, Some(Default)),
    (227, "postNAPTSourceTransportPort", Unsigned16, Some(Identifier)),
    (228, "postNAPTDestinationTransportPort", Unsigned16, Some(Identifier)),
    (229, "natOriginatingAddressRealm", Unsigned8, Some(Identifier)),
    (230, "natEvent", Unsigned8, Some(Identifier)),
    (231, "initiatorOctets", Unsigned64, Some(DeltaCounter)),
    (232, "responderOctets", Unsigned64, Some(DeltaCounter)),
    (233, "firewallEvent", Unsigned8, None),
    (234, "ingressVRFID", Unsigned32, None),
    (235, "egressVRFID", Unsigned32, None),
    (236, "VRFname", String, Some(Default)),
    (237, "postMplsTopLabelExp", Unsigned8, Some(Flags)),
    (238, "tcpWindowScale", Unsigned16, None),
    (239, "biflowDirection", Unsigned8, Some(Identifier)),
    (240, "ethernetHeaderLength", Unsigned8, Some(Quantity)),
    (241, "ethernetPayloadLength", Unsigned16, Some(Quantity)),
    (242, "ethernetTotalLength", Unsigned16, Some(Quantity)),
    (243, "dot1qVlanId", Unsigned16, Some(Identifier)),
    (244, "dot1qPriority", Unsigned8, Some(Identifier)),
    (245, "dot1qCustomerVlanId", Unsigned16, Some(Identifier)),
    (246, "dot1qCustomerPriority", Unsigned8, Some(Identifier)),
    (247, "metroEvcId", String, Some(Default)),
    (248, "metroEvcType", Unsigned8, Some(Identifier)),
    (249, "pseudoWireId", Unsigned32, Some(Identifier)),
    (250, "pseudoWireType", Unsigned16, Some(Identifier)),
    (251, "pseudoWireControlWord", Unsigned32, Some(Identifier)),
    (252, "ingressPhysicalInterface", Unsigned32, Some(Identifier)),
    (253, "egressPhysicalInterface", Unsigned32, Some(Identifier)),
    (254, "postDot1qVlanId", Unsigned16, Some(Identifier)),
    (255, "postDot1qCustomerVlanId", Unsigned16, Some(Identifier)),
    (256, "ethernetType", Unsigned16, Some(Identifier)),
    (257, "postIpPrecedence", Unsigned8, Some(Identifier)),
    (258, "collectionTimeMilliseconds", DateTimeMilliseconds, Some(Default)),
    (259, "exportSctpStreamId", Unsigned16, Some(Identifier)),
    (260, "maxExportSeconds", DateTimeSeconds, Some(Default)),
    (261, "maxFlowEndSeconds", DateTimeSeconds, Some(Default)),
    (262, "messageMD5Checksum", OctetArray, Some(Default)),
    (263, "messageScope", Unsigned8, None),
    (264, "minExportSeconds", DateTimeSeconds, Some(Default)),
    (265, "minFlowStartSeconds", DateTimeSeconds, Some(Default)),
    (266, "opaqueOctets", OctetArray, Some(Default)),
    (267, "sessionScope", Unsigned8, None),
    (268, "maxFlowEndMicroseconds", DateTimeMicroseconds, Some(Default)),
    (269, "maxFlowEndMilliseconds", DateTimeMilliseconds, Some(Default)),
    (270, "maxFlowEndNanoseconds", DateTimeNanoseconds, Some(Default)),
    (271, "minFlowStartMicroseconds", DateTimeMicroseconds, Some(Default)),
    (272, "minFlowStartMilliseconds", DateTimeMilliseconds, Some(Default)),
    (273, "minFlowStartNanoseconds", DateTimeNanoseconds, Some(Default)),
    (274, "collectorCertificate", OctetArray, Some(Default)),
    (275, "exporterCertificate", OctetArray, Some(Default)),
    (276, "dataRecordsReliability", Boolean, Some(Default)),
    (277, "observationPointType", Unsigned8, Some(Identifier)),
    (278, "newConnectionDeltaCount", Unsigned32, Some(DeltaCounter)),
    (279, "connectionSumDurationSeconds", Unsigned64, None),
    (280, "connectionTransactionId", Unsigned64, Some(Identifier)),
    (281, "postNATSourceIPv6Address", Ipv6Address, Some(Default)),
    (282, "postNATDestinationIPv6Address", Ipv6Address, Some(Default)),
    (283, "natPoolId", Unsigned32, Some(Identifier)),
    (284, "natPoolName", String, Some(Default)),
    (285, "anonymizationFlags", Unsigned16, Some(Flags)),
    (286, "anonymizationTechnique", Unsigned16, Some(Identifier)),
    (287, "informationElementIndex", Unsigned16, Some(Identifier)),
    (288, "p2pTechnology", String, Some(Default)),
    (289, "tunnelTechnology", String, Some(Default)),
    (290, "encryptedTechnology", String, Some(Default)),
    (291, "basicList", BasicList, Some(List)),
    (292, "subTemplateList", SubTemplateList, Some(List)),
    (293, "subTemplateMultiList", SubTemplateMultiList, Some(List)),
    (294, "bgpValidityState", Unsigned8, Some(Identifier)),
    (295, "IPSecSPI", Unsigned32, Some(Identifier)),
    (296, "greKey", Unsigned32, Some(Identifier)),
    (297, "natType", Unsigned8, Some(Identifier)),
    (298, "initiatorPackets", Unsigned64, Some(DeltaCounter)),
    (299, "responderPackets", Unsigned64, Some(DeltaCounter)),
    (300, "observationDomainName", String, Some(Default)),
    (301, "selectionSequenceId", Unsigned64, Some(Identifier)),
    (302, "selectorId", Unsigned64, Some(Identifier)),
    (303, "informationElementId", Unsigned16, Some(Identifier)),
    (304, "selectorAlgorithm", Unsigned16, Some(Identifier)),
    (305, "samplingPacketInterval", Unsigned32, Some(Quantity)),
    (306, "samplingPacketSpace", Unsigned32, Some(Quantity)),
    (307, "samplingTimeInterval", Unsigned32, Some(Quantity)),
    (308, "samplingTimeSpace", Unsigned32, Some(Quantity)),
    (309, "samplingSize", Unsigned32, Some(Quantity)),
    (310, "samplingPopulation", Unsigned32, Some(Quantity)),
    (311, "samplingProbability", Float64, Some(Quantity)),
    (312, "dataLinkFrameSize", Unsigned16, Some(Quantity)),
    (313, "ipHeaderPacketSection", OctetArray, Some(Default)),
    (314, "ipPayloadPacketSection", OctetArray, Some(Default)),
    (315, "dataLinkFrameSection", OctetArray, Some(Default)),
    (316, "mplsLabelStackSection", OctetArray, Some(Default)),
    (317, "mplsPayloadPacketSection", OctetArray, Some(Default)),
    (318, "selectorIdTotalPktsObserved", Unsigned64, Some(TotalCounter)),
    (319, "selectorIdTotalPktsSelected", Unsigned64, Some(TotalCounter)),
    (320, "absoluteError", Float64, Some(Quantity)),
    (321, "relativeError", Float64, Some(Quantity)),
    (322, "observationTimeSeconds", DateTimeSeconds, Some(Default)),
    (323, "observationTimeMilliseconds", DateTimeMilliseconds, Some(Default)),
    (324, "observationTimeMicroseconds", DateTimeMicroseconds, Some(Default)),
    (325, "observationTimeNanoseconds", DateTimeNanoseconds, Some(Default)),
    (326, "digestHashValue", Unsigned64, Some(Quantity)),
    (327, "hashIPPayloadOffset", Unsigned64, Some(Quantity)),
    (328, "hashIPPayloadSize", Unsigned64, Some(Quantity)),
    (329, "hashOutputRangeMin", Unsigned64, Some(Quantity)),
    (330, "hashOutputRangeMax", Unsigned64, Some(Quantity)),
    (331, "hashSelectedRangeMin", Unsigned64, Some(Quantity)),
    (332, "hashSelectedRangeMax", Unsigned64, Some(Quantity)),
    (333, "hashDigestOutput", Boolean, Some(Default)),
    (334, "hashInitialiserValue", Unsigned64, Some(Quantity)),
    (335, "selectorName", String, Some(Default)),
    (336, "upperCILimit", Float64, Some(Quantity)),
    (337, "lowerCILimit", Float64, Some(Quantity)),
    (338, "confidenceLevel", Float64, Some(Quantity)),
    (339, "informationElementDataType", Unsigned8, None),
    (340, "informationElementDescription", String, Some(Default)),
    (341, "informationElementName", String, Some(Default)),
    (342, "informationElementRangeBegin", Unsigned64, Some(Quantity)),
    (343, "informationElementRangeEnd", Unsigned64, Some(Quantity)),
    (344, "informationElementSemantics", Unsigned8, None),
    (345, "informationElementUnits", Unsigned16, None),
    (346, "privateEnterpriseNumber", Unsigned32, Some(Identifier)),
    (347, "virtualStationInterfaceId", OctetArray, Some(Default)),
    (348, "virtualStationInterfaceName", String, Some(Default)),
    (349, "virtualStationUUID", OctetArray, Some(Default)),
    (350, "virtualStationName", String, Some(Default)),
    (351, "layer2SegmentId", Unsigned64, Some(Identifier)),
    (352, "layer2OctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (353, "layer2OctetTotalCount", Unsigned64, Some(TotalCounter)),
    (354, "ingressUnicastPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (355, "ingressMulticastPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (356, "ingressBroadcastPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (357, "egressUnicastPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (358, "egressBroadcastPacketTotalCount", Unsigned64, Some(TotalCounter)),
    (359, "monitoringIntervalStartMilliSeconds", DateTimeMilliseconds, Some(Default)),
    (360, "monitoringIntervalEndMilliSeconds", DateTimeMilliseconds, Some(Default)),
    (361, "portRangeStart", Unsigned16, Some(Identifier)),
    (362, "portRangeEnd", Unsigned16, Some(Identifier)),
    (363, "portRangeStepSize", Unsigned16, Some(Identifier)),
    (364, "portRangeNumPorts", Unsigned16, Some(Identifier)),
    (365, "staMacAddress", MacAddress, Some(Default)),
    (366, "staIPv4Address", Ipv4Address, Some(Default)),
    (367, "wtpMacAddress", MacAddress, Some(Default)),
    (368, "ingressInterfaceType", Unsigned32, Some(Identifier)),
    (369, "egressInterfaceType", Unsigned32, Some(Identifier)),
    (370, "rtpSequenceNumber", Unsigned16, None),
    (371, "userName", String, Some(Default)),
    (372, "applicationCategoryName", String, Some(Default)),
    (373, "applicationSubCategoryName", String, Some(Default)),
    (374, "applicationGroupName", String, Some(Default)),
    (375, "originalFlowsPresent", Unsigned64, Some(DeltaCounter)),
    (376, "originalFlowsInitiated", Unsigned64, Some(DeltaCounter)),
    (377, "originalFlowsCompleted", Unsigned64, Some(DeltaCounter)),
    (378, "distinctCountOfSourceIPAddress", Unsigned64, Some(TotalCounter)),
    (379, "distinctCountOfDestinationIPAddress", Unsigned64, Some(TotalCounter)),
    (380, "distinctCountOfSourceIPv4Address", Unsigned32, Some(TotalCounter)),
    (381, "distinctCountOfDestinationIPv4Address", Unsigned32, Some(TotalCounter)),
    (382, "distinctCountOfSourceIPv6Address", Unsigned64, Some(TotalCounter)),
    (383, "distinctCountOfDestinationIPv6Address", Unsigned64, Some(TotalCounter)),
    (384, "valueDistributionMethod", Unsigned8, None),
    (385, "rfc3550JitterMilliseconds", Unsigned32, Some(Quantity)),
    (386, "rfc3550JitterMicroseconds", Unsigned32, Some(Quantity)),
    (387, "rfc3550JitterNanoseconds", Unsigned32, Some(Quantity)),
    (388, "dot1qDEI", Boolean, Some(Default)),
    (389, "dot1qCustomerDEI", Boolean, Some(Default)),
    (390, "flowSelectorAlgorithm", Unsigned16, Some(Identifier)),
    (391, "flowSelectedOctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (392, "flowSelectedPacketDeltaCount", Unsigned64, Some(DeltaCounter)),
    (393, "flowSelectedFlowDeltaCount", Unsigned64, Some(DeltaCounter)),
    (394, "selectorIDTotalFlowsObserved", Unsigned64, None),
    (395, "selectorIDTotalFlowsSelected", Unsigned64, None),
    (396, "samplingFlowInterval", Unsigned64, None),
    (397, "samplingFlowSpacing", Unsigned64, None),
    (398, "flowSamplingTimeInterval", Unsigned64, None),
    (399, "flowSamplingTimeSpacing", Unsigned64, None),
    (400, "hashFlowDomain", Unsigned16, Some(Identifier)),
    (401, "transportOctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (402, "transportPacketDeltaCount", Unsigned64, Some(DeltaCounter)),
    (403, "originalExporterIPv4Address", Ipv4Address, None),
    (404, "originalExporterIPv6Address", Ipv6Address, None),
    (405, "originalObservationDomainId", Unsigned32, Some(Identifier)),
    (406, "intermediateProcessId", Unsigned32, Some(Identifier)),
    (407, "ignoredDataRecordTotalCount", Unsigned64, Some(TotalCounter)),
    (408, "dataLinkFrameType", Unsigned16, Some(Flags)),
    (409, "sectionOffset", Unsigned16, Some(Quantity)),
    (410, "sectionExportedOctets", Unsigned16, Some(Quantity)),
    (411, "dot1qServiceInstanceTag", OctetArray, Some(Default)),
    (412, "dot1qServiceInstanceId", Unsigned32, Some(Identifier)),
    (413, "dot1qServiceInstancePriority", Unsigned8, Some(Identifier)),
    (414, "dot1qCustomerSourceMacAddress", MacAddress, Some(Default)),
    (415, "dot1qCustomerDestinationMacAddress", MacAddress, Some(Default)),
    (417, "postLayer2OctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (418, "postMCastLayer2OctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (420, "postLayer2OctetTotalCount", Unsigned64, Some(TotalCounter)),
    (421, "postMCastLayer2OctetTotalCount", Unsigned64, Some(TotalCounter)),
    (422, "minimumLayer2TotalLength", Unsigned64, None),
    (423, "maximumLayer2TotalLength", Unsigned64, None),
    (424, "droppedLayer2OctetDeltaCount", Unsigned64, Some(DeltaCounter)),
    (425, "droppedLayer2OctetTotalCount", Unsigned64, Some(TotalCounter)),
    (426, "ignoredLayer2OctetTotalCount", Unsigned64, Some(TotalCounter)),
    (427, "notSentLayer2OctetTotalCount", Unsigned64, Some(TotalCounter)),
    (428, "layer2OctetDeltaSumOfSquares", Unsigned64, Some(DeltaCounter)),
    (429, "layer2OctetTotalSumOfSquares", Unsigned64, Some(TotalCounter)),
    (430, "layer2FrameDeltaCount", Unsigned64, Some(DeltaCounter)),
    (431, "layer2FrameTotalCount", Unsigned64, Some(TotalCounter)),
    (432, "pseudoWireDestinationIPv4Address", Ipv4Address, Some(Default)),
    (433, "ignoredLayer2FrameTotalCount", Unsigned64, Some(TotalCounter)),
    (434, "mibObjectValueInteger", Signed32, Some(Quantity)),
    (435, "mibObjectValueOctetString", OctetArray, Some(Default)),
    (436, "mibObjectValueOID", OctetArray, Some(Default)),
    (437, "mibObjectValueBits", OctetArray, Some(Flags)),
    (438, "mibObjectValueIPAddress", Ipv4Address, Some(Default)),
    (439, "mibObjectValueCounter", Unsigned64, Some(SnmpCounter)),
    (440, "mibObjectValueGauge", Unsigned32, Some(SnmpGauge)),
    (441, "mibObjectValueTimeTicks", Unsigned32, Some(Quantity)),
    (442, "mibObjectValueUnsigned", Unsigned32, Some(Quantity)),
    (443, "mibObjectValueTable", SubTemplateList, Some(List)),
    (444, "mibObjectValueRow", SubTemplateList, Some(List)),
    (445, "mibObjectIdentifier", OctetArray, Some(Default)),
    (446, "mibSubIdentifier", Unsigned32, Some(Identifier)),
    (447, "mibIndexIndicator", Unsigned64, Some(Flags)),
    (448, "mibCaptureTimeSemantics", Unsigned8, Some(Identifier)),
    (449, "mibContextEngineID", OctetArray, Some(Default)),
    (450, "mibContextName", String, Some(Default)),
    (451, "mibObjectName", String, Some(Default)),
    (452, "mibObjectDescription", String, Some(Default)),
    (453, "mibObjectSyntax", String, Some(Default)),
    (454, "mibModuleName", String, Some(Default)),
    (455, "mobileIMSI", String, Some(Default)),
    (456, "mobileMSISDN", String, Some(Default)),
    (457, "httpStatusCode", Unsigned16, Some(Identifier)),
    (458, "sourceTransportPortsLimit", Unsigned16, Some(Quantity)),
    (459, "httpRequestMethod", String, None),
    (460, "httpRequestHost", String, None),
    (461, "httpRequestTarget", String, None),
    (462, "httpMessageVersion", String, None),
    (463, "natInstanceID", Unsigned32, Some(Identifier)),
    (464, "internalAddressRealm", OctetArray, Some(Identifier)),
    (465, "externalAddressRealm", OctetArray, Some(Identifier)),
    (466, "natQuotaExceededEvent", Unsigned32, Some(Identifier)),
    (467, "natThresholdEvent", Unsigned32, Some(Identifier)),
    (468, "httpUserAgent", String, Some(Default)),
    (469, "httpContentType", String, Some(Default)),
    (470, "httpReasonPhrase", String, Some(Default)),
    (471, "maxSessionEntries", Unsigned32, Some(Identifier)),
    (472, "maxBIBEntries", Unsigned32, Some(Identifier)),
    (473, "maxEntriesPerUser", Unsigned32, Some(Identifier)),
    (474, "maxSubscribers", Unsigned32, Some(Identifier)),
    (475, "maxFragmentsPendingReassembly", Unsigned32, Some(Identifier)),
    (476, "addressPoolHighThreshold", Unsigned32, Some(Identifier)),
    (477, "addressPoolLowThreshold", Unsigned32, Some(Identifier)),
    (478, "addressPortMappingHighThreshold", Unsigned32, Some(Identifier)),
    (479, "addressPortMappingLowThreshold", Unsigned32, Some(Identifier)),
    (480, "addressPortMappingPerUserHighThreshold", Unsigned32, Some(Identifier)),
    (481, "globalAddressMappingHighThreshold", Unsigned32, Some(Identifier)),
    (482, "vpnIdentifier", OctetArray, Some(Default)),
    (483, "bgpCommunity", Unsigned32, Some(Identifier)),
    (484, "bgpSourceCommunityList", BasicList, Some(List)),
    (485, "bgpDestinationCommunityList", BasicList, Some(List)),
    (486, "bgpExtendedCommunity", OctetArray, Some(Default)),
    (487, "bgpSourceExtendedCommunityList", BasicList, Some(List)),
    (488, "bgpDestinationExtendedCommunityList", BasicList, Some(List)),
    (489, "bgpLargeCommunity", OctetArray, Some(Default)),
    (490, "bgpSourceLargeCommunityList", BasicList, Some(List)),
    (491, "bgpDestinationLargeCommunityList", BasicList, Some(List)),
    (492, "srhFlagsIPv6", Unsigned8, Some(Flags)),
    (493, "srhTagIPv6", Unsigned16, Some(Identifier)),
    (494, "srhSegmentIPv6", Ipv6Address, Some(Default)),
    (495, "srhActiveSegmentIPv6", Ipv6Address, Some(Default)),
    (496, "srhSegmentIPv6BasicList", BasicList, Some(List)),
    (497, "srhSegmentIPv6ListSection", OctetArray, Some(Default)),
    (498, "srhSegmentsIPv6Left", Unsigned8, Some(Quantity)),
    (499, "srhIPv6Section", OctetArray, Some(Default)),
    (500, "srhIPv6ActiveSegmentType", Unsigned8, Some(Identifier)),
    (501, "srhSegmentIPv6LocatorLength", Unsigned8, Some(Default)),
    (502, "srhSegmentIPv6EndpointBehavior", Unsigned16, Some(Identifier)),
    (503, "transportChecksum", Unsigned16, Some(Default)),
    (504, "icmpHeaderPacketSection", OctetArray, Some(Default)),
    (505, "gtpuFlags", Unsigned8, Some(Flags)),
    (506, "gtpuMsgType", Unsigned8, Some(Identifier)),
    (507, "gtpuTEid", Unsigned32, Some(Identifier)),
    (508, "gtpuSequenceNum", Unsigned16, Some(Identifier)),
    (509, "gtpuQFI", Unsigned8, Some(Identifier)),
    (510, "gtpuPduType", Unsigned8, Some(Identifier)),
    (511, "bgpSourceAsPathList", BasicList, Some(List)),
    (512, "bgpDestinationAsPathList", BasicList, Some(List)),
    (513, "ipv6ExtensionHeaderType", Unsigned8, Some(Identifier)),
    (514, "ipv6ExtensionHeaderCount", Unsigned8, Some(TotalCounter)),
    (515, "ipv6ExtensionHeadersFull", Unsigned256, Some(Flags)),
    (516, "ipv6ExtensionHeaderTypeCountList", SubTemplateList, Some(List)),
    (517, "ipv6ExtensionHeadersLimit", Boolean, Some(Default)),
    (518, "ipv6ExtensionHeadersChainLength", Unsigned32, Some(Identifier)),
    (519, "ipv6ExtensionHeaderChainLengthList", SubTemplateList, Some(List)),
    (520, "tcpOptionsFull", Unsigned256, Some(Flags)),
    (521, "tcpSharedOptionExID16", Unsigned16, Some(Identifier)),
    (522, "tcpSharedOptionExID32", Unsigned32, Some(Identifier)),
    (523, "tcpSharedOptionExID16List", BasicList, Some(List)),
    (524, "tcpSharedOptionExID32List", BasicList, Some(List)),
    (525, "udpSafeOptions", Unsigned256, Some(Flags)),
    (526, "udpUnsafeOptions", Unsigned64, Some(Flags)),
    (527, "udpExID", Unsigned16, Some(Identifier)),
    (528, "udpSafeExIDList", BasicList, Some(List)),
    (529, "udpUnsafeExIDList", BasicList, Some(List)),
    (530, "pathDelayMeanDeltaMicroseconds", Unsigned32, Some(DeltaCounter)),
    (531, "pathDelayMinDeltaMicroseconds", Unsigned32, Some(DeltaCounter)),
    (532, "pathDelayMaxDeltaMicroseconds", Unsigned32, Some(DeltaCounter)),
    (533, "pathDelaySumDeltaMicroseconds", Unsigned64, Some(DeltaCounter)),
];

impl ElementId {
    /// `octetDeltaCount`
    pub const OCTET_DELTA_COUNT: Self = Self::iana(1);
    /// `packetDeltaCount`
    pub const PACKET_DELTA_COUNT: Self = Self::iana(2);
    /// `deltaFlowCount`
    pub const DELTA_FLOW_COUNT: Self = Self::iana(3);
    /// `protocolIdentifier`
    pub const PROTOCOL_IDENTIFIER: Self = Self::iana(4);
    /// `ipClassOfService`
    pub const IP_CLASS_OF_SERVICE: Self = Self::iana(5);
    /// `tcpControlBits`
    pub const TCP_CONTROL_BITS: Self = Self::iana(6);
    /// `sourceTransportPort`
    pub const SOURCE_TRANSPORT_PORT: Self = Self::iana(7);
    /// `sourceIPv4Address`
    pub const SOURCE_IPV4_ADDRESS: Self = Self::iana(8);
    /// `sourceIPv4PrefixLength`
    pub const SOURCE_IPV4_PREFIX_LENGTH: Self = Self::iana(9);
    /// `ingressInterface`
    pub const INGRESS_INTERFACE: Self = Self::iana(10);
    /// `destinationTransportPort`
    pub const DESTINATION_TRANSPORT_PORT: Self = Self::iana(11);
    /// `destinationIPv4Address`
    pub const DESTINATION_IPV4_ADDRESS: Self = Self::iana(12);
    /// `destinationIPv4PrefixLength`
    pub const DESTINATION_IPV4_PREFIX_LENGTH: Self = Self::iana(13);
    /// `egressInterface`
    pub const EGRESS_INTERFACE: Self = Self::iana(14);
    /// `ipNextHopIPv4Address`
    pub const IP_NEXT_HOP_IPV4_ADDRESS: Self = Self::iana(15);
    /// `bgpSourceAsNumber`
    pub const BGP_SOURCE_AS_NUMBER: Self = Self::iana(16);
    /// `bgpDestinationAsNumber`
    pub const BGP_DESTINATION_AS_NUMBER: Self = Self::iana(17);
    /// `bgpNextHopIPv4Address`
    pub const BGP_NEXT_HOP_IPV4_ADDRESS: Self = Self::iana(18);
    /// `postMCastPacketDeltaCount`
    pub const POST_MCAST_PACKET_DELTA_COUNT: Self = Self::iana(19);
    /// `postMCastOctetDeltaCount`
    pub const POST_MCAST_OCTET_DELTA_COUNT: Self = Self::iana(20);
    /// `flowEndSysUpTime`
    pub const FLOW_END_SYS_UP_TIME: Self = Self::iana(21);
    /// `flowStartSysUpTime`
    pub const FLOW_START_SYS_UP_TIME: Self = Self::iana(22);
    /// `postOctetDeltaCount`
    pub const POST_OCTET_DELTA_COUNT: Self = Self::iana(23);
    /// `postPacketDeltaCount`
    pub const POST_PACKET_DELTA_COUNT: Self = Self::iana(24);
    /// `minimumIpTotalLength`
    pub const MINIMUM_IP_TOTAL_LENGTH: Self = Self::iana(25);
    /// `maximumIpTotalLength`
    pub const MAXIMUM_IP_TOTAL_LENGTH: Self = Self::iana(26);
    /// `sourceIPv6Address`
    pub const SOURCE_IPV6_ADDRESS: Self = Self::iana(27);
    /// `destinationIPv6Address`
    pub const DESTINATION_IPV6_ADDRESS: Self = Self::iana(28);
    /// `sourceIPv6PrefixLength`
    pub const SOURCE_IPV6_PREFIX_LENGTH: Self = Self::iana(29);
    /// `destinationIPv6PrefixLength`
    pub const DESTINATION_IPV6_PREFIX_LENGTH: Self = Self::iana(30);
    /// `flowLabelIPv6`
    pub const FLOW_LABEL_IPV6: Self = Self::iana(31);
    /// `icmpTypeCodeIPv4`
    pub const ICMP_TYPE_CODE_IPV4: Self = Self::iana(32);
    /// `igmpType`
    pub const IGMP_TYPE: Self = Self::iana(33);
    /// `samplingInterval`
    pub const SAMPLING_INTERVAL: Self = Self::iana(34);
    /// `samplingAlgorithm`
    pub const SAMPLING_ALGORITHM: Self = Self::iana(35);
    /// `flowActiveTimeout`
    pub const FLOW_ACTIVE_TIMEOUT: Self = Self::iana(36);
    /// `flowIdleTimeout`
    pub const FLOW_IDLE_TIMEOUT: Self = Self::iana(37);
    /// `engineType`
    pub const ENGINE_TYPE: Self = Self::iana(38);
    /// `engineId`
    pub const ENGINE_ID: Self = Self::iana(39);
    /// `exportedOctetTotalCount`
    pub const EXPORTED_OCTET_TOTAL_COUNT: Self = Self::iana(40);
    /// `exportedMessageTotalCount`
    pub const EXPORTED_MESSAGE_TOTAL_COUNT: Self = Self::iana(41);
    /// `exportedFlowRecordTotalCount`
    pub const EXPORTED_FLOW_RECORD_TOTAL_COUNT: Self = Self::iana(42);
    /// `ipv4RouterSc`
    pub const IPV4_ROUTER_SC: Self = Self::iana(43);
    /// `sourceIPv4Prefix`
    pub const SOURCE_IPV4_PREFIX: Self = Self::iana(44);
    /// `destinationIPv4Prefix`
    pub const DESTINATION_IPV4_PREFIX: Self = Self::iana(45);
    /// `mplsTopLabelType`
    pub const MPLS_TOP_LABEL_TYPE: Self = Self::iana(46);
    /// `mplsTopLabelIPv4Address`
    pub const MPLS_TOP_LABEL_IPV4_ADDRESS: Self = Self::iana(47);
    /// `samplerId`
    pub const SAMPLER_ID: Self = Self::iana(48);
    /// `samplerMode`
    pub const SAMPLER_MODE: Self = Self::iana(49);
    /// `samplerRandomInterval`
    pub const SAMPLER_RANDOM_INTERVAL: Self = Self::iana(50);
    /// `classId`
    pub const CLASS_ID: Self = Self::iana(51);
    /// `minimumTTL`
    pub const MINIMUM_TTL: Self = Self::iana(52);
    /// `maximumTTL`
    pub const MAXIMUM_TTL: Self = Self::iana(53);
    /// `fragmentIdentification`
    pub const FRAGMENT_IDENTIFICATION: Self = Self::iana(54);
    /// `postIpClassOfService`
    pub const POST_IP_CLASS_OF_SERVICE: Self = Self::iana(55);
    /// `sourceMacAddress`
    pub const SOURCE_MAC_ADDRESS: Self = Self::iana(56);
    /// `postDestinationMacAddress`
    pub const POST_DESTINATION_MAC_ADDRESS: Self = Self::iana(57);
    /// `vlanId`
    pub const VLAN_ID: Self = Self::iana(58);
    /// `postVlanId`
    pub const POST_VLAN_ID: Self = Self::iana(59);
    /// `ipVersion`
    pub const IP_VERSION: Self = Self::iana(60);
    /// `flowDirection`
    pub const FLOW_DIRECTION: Self = Self::iana(61);
    /// `ipNextHopIPv6Address`
    pub const IP_NEXT_HOP_IPV6_ADDRESS: Self = Self::iana(62);
    /// `bgpNextHopIPv6Address`
    pub const BGP_NEXT_HOP_IPV6_ADDRESS: Self = Self::iana(63);
    /// `ipv6ExtensionHeaders`
    pub const IPV6_EXTENSION_HEADERS: Self = Self::iana(64);
    /// `mplsTopLabelStackSection`
    pub const MPLS_TOP_LABEL_STACK_SECTION: Self = Self::iana(70);
    /// `mplsLabelStackSection2`
    pub const MPLS_LABEL_STACK_SECTION2: Self = Self::iana(71);
    /// `mplsLabelStackSection3`
    pub const MPLS_LABEL_STACK_SECTION3: Self = Self::iana(72);
    /// `mplsLabelStackSection4`
    pub const MPLS_LABEL_STACK_SECTION4: Self = Self::iana(73);
    /// `mplsLabelStackSection5`
    pub const MPLS_LABEL_STACK_SECTION5: Self = Self::iana(74);
    /// `mplsLabelStackSection6`
    pub const MPLS_LABEL_STACK_SECTION6: Self = Self::iana(75);
    /// `mplsLabelStackSection7`
    pub const MPLS_LABEL_STACK_SECTION7: Self = Self::iana(76);
    /// `mplsLabelStackSection8`
    pub const MPLS_LABEL_STACK_SECTION8: Self = Self::iana(77);
    /// `mplsLabelStackSection9`
    pub const MPLS_LABEL_STACK_SECTION9: Self = Self::iana(78);
    /// `mplsLabelStackSection10`
    pub const MPLS_LABEL_STACK_SECTION10: Self = Self::iana(79);
    /// `destinationMacAddress`
    pub const DESTINATION_MAC_ADDRESS: Self = Self::iana(80);
    /// `postSourceMacAddress`
    pub const POST_SOURCE_MAC_ADDRESS: Self = Self::iana(81);
    /// `interfaceName`
    pub const INTERFACE_NAME: Self = Self::iana(82);
    /// `interfaceDescription`
    pub const INTERFACE_DESCRIPTION: Self = Self::iana(83);
    /// `samplerName`
    pub const SAMPLER_NAME: Self = Self::iana(84);
    /// `octetTotalCount`
    pub const OCTET_TOTAL_COUNT: Self = Self::iana(85);
    /// `packetTotalCount`
    pub const PACKET_TOTAL_COUNT: Self = Self::iana(86);
    /// `flagsAndSamplerId`
    pub const FLAGS_AND_SAMPLER_ID: Self = Self::iana(87);
    /// `fragmentOffset`
    pub const FRAGMENT_OFFSET: Self = Self::iana(88);
    /// `forwardingStatus`
    pub const FORWARDING_STATUS: Self = Self::iana(89);
    /// `mplsVpnRouteDistinguisher`
    pub const MPLS_VPN_ROUTE_DISTINGUISHER: Self = Self::iana(90);
    /// `mplsTopLabelPrefixLength`
    pub const MPLS_TOP_LABEL_PREFIX_LENGTH: Self = Self::iana(91);
    /// `srcTrafficIndex`
    pub const SRC_TRAFFIC_INDEX: Self = Self::iana(92);
    /// `dstTrafficIndex`
    pub const DST_TRAFFIC_INDEX: Self = Self::iana(93);
    /// `applicationDescription`
    pub const APPLICATION_DESCRIPTION: Self = Self::iana(94);
    /// `applicationId`
    pub const APPLICATION_ID: Self = Self::iana(95);
    /// `applicationName`
    pub const APPLICATION_NAME: Self = Self::iana(96);
    /// `postIpDiffServCodePoint`
    pub const POST_IP_DIFF_SERV_CODE_POINT: Self = Self::iana(98);
    /// `multicastReplicationFactor`
    pub const MULTICAST_REPLICATION_FACTOR: Self = Self::iana(99);
    /// `className`
    pub const CLASS_NAME: Self = Self::iana(100);
    /// `classificationEngineId`
    pub const CLASSIFICATION_ENGINE_ID: Self = Self::iana(101);
    /// `layer2packetSectionOffset`
    pub const LAYER2PACKET_SECTION_OFFSET: Self = Self::iana(102);
    /// `layer2packetSectionSize`
    pub const LAYER2PACKET_SECTION_SIZE: Self = Self::iana(103);
    /// `layer2packetSectionData`
    pub const LAYER2PACKET_SECTION_DATA: Self = Self::iana(104);
    /// `bgpNextAdjacentAsNumber`
    pub const BGP_NEXT_ADJACENT_AS_NUMBER: Self = Self::iana(128);
    /// `bgpPrevAdjacentAsNumber`
    pub const BGP_PREV_ADJACENT_AS_NUMBER: Self = Self::iana(129);
    /// `exporterIPv4Address`
    pub const EXPORTER_IPV4_ADDRESS: Self = Self::iana(130);
    /// `exporterIPv6Address`
    pub const EXPORTER_IPV6_ADDRESS: Self = Self::iana(131);
    /// `droppedOctetDeltaCount`
    pub const DROPPED_OCTET_DELTA_COUNT: Self = Self::iana(132);
    /// `droppedPacketDeltaCount`
    pub const DROPPED_PACKET_DELTA_COUNT: Self = Self::iana(133);
    /// `droppedOctetTotalCount`
    pub const DROPPED_OCTET_TOTAL_COUNT: Self = Self::iana(134);
    /// `droppedPacketTotalCount`
    pub const DROPPED_PACKET_TOTAL_COUNT: Self = Self::iana(135);
    /// `flowEndReason`
    pub const FLOW_END_REASON: Self = Self::iana(136);
    /// `commonPropertiesId`
    pub const COMMON_PROPERTIES_ID: Self = Self::iana(137);
    /// `observationPointId`
    pub const OBSERVATION_POINT_ID: Self = Self::iana(138);
    /// `icmpTypeCodeIPv6`
    pub const ICMP_TYPE_CODE_IPV6: Self = Self::iana(139);
    /// `mplsTopLabelIPv6Address`
    pub const MPLS_TOP_LABEL_IPV6_ADDRESS: Self = Self::iana(140);
    /// `lineCardId`
    pub const LINE_CARD_ID: Self = Self::iana(141);
    /// `portId`
    pub const PORT_ID: Self = Self::iana(142);
    /// `meteringProcessId`
    pub const METERING_PROCESS_ID: Self = Self::iana(143);
    /// `exportingProcessId`
    pub const EXPORTING_PROCESS_ID: Self = Self::iana(144);
    /// `templateId`
    pub const TEMPLATE_ID: Self = Self::iana(145);
    /// `wlanChannelId`
    pub const WLAN_CHANNEL_ID: Self = Self::iana(146);
    /// `wlanSSID`
    pub const WLAN_SSID: Self = Self::iana(147);
    /// `flowId`
    pub const FLOW_ID: Self = Self::iana(148);
    /// `observationDomainId`
    pub const OBSERVATION_DOMAIN_ID: Self = Self::iana(149);
    /// `flowStartSeconds`
    pub const FLOW_START_SECONDS: Self = Self::iana(150);
    /// `flowEndSeconds`
    pub const FLOW_END_SECONDS: Self = Self::iana(151);
    /// `flowStartMilliseconds`
    pub const FLOW_START_MILLISECONDS: Self = Self::iana(152);
    /// `flowEndMilliseconds`
    pub const FLOW_END_MILLISECONDS: Self = Self::iana(153);
    /// `flowStartMicroseconds`
    pub const FLOW_START_MICROSECONDS: Self = Self::iana(154);
    /// `flowEndMicroseconds`
    pub const FLOW_END_MICROSECONDS: Self = Self::iana(155);
    /// `flowStartNanoseconds`
    pub const FLOW_START_NANOSECONDS: Self = Self::iana(156);
    /// `flowEndNanoseconds`
    pub const FLOW_END_NANOSECONDS: Self = Self::iana(157);
    /// `flowStartDeltaMicroseconds`
    pub const FLOW_START_DELTA_MICROSECONDS: Self = Self::iana(158);
    /// `flowEndDeltaMicroseconds`
    pub const FLOW_END_DELTA_MICROSECONDS: Self = Self::iana(159);
    /// `systemInitTimeMilliseconds`
    pub const SYSTEM_INIT_TIME_MILLISECONDS: Self = Self::iana(160);
    /// `flowDurationMilliseconds`
    pub const FLOW_DURATION_MILLISECONDS: Self = Self::iana(161);
    /// `flowDurationMicroseconds`
    pub const FLOW_DURATION_MICROSECONDS: Self = Self::iana(162);
    /// `observedFlowTotalCount`
    pub const OBSERVED_FLOW_TOTAL_COUNT: Self = Self::iana(163);
    /// `ignoredPacketTotalCount`
    pub const IGNORED_PACKET_TOTAL_COUNT: Self = Self::iana(164);
    /// `ignoredOctetTotalCount`
    pub const IGNORED_OCTET_TOTAL_COUNT: Self = Self::iana(165);
    /// `notSentFlowTotalCount`
    pub const NOT_SENT_FLOW_TOTAL_COUNT: Self = Self::iana(166);
    /// `notSentPacketTotalCount`
    pub const NOT_SENT_PACKET_TOTAL_COUNT: Self = Self::iana(167);
    /// `notSentOctetTotalCount`
    pub const NOT_SENT_OCTET_TOTAL_COUNT: Self = Self::iana(168);
    /// `destinationIPv6Prefix`
    pub const DESTINATION_IPV6_PREFIX: Self = Self::iana(169);
    /// `sourceIPv6Prefix`
    pub const SOURCE_IPV6_PREFIX: Self = Self::iana(170);
    /// `postOctetTotalCount`
    pub const POST_OCTET_TOTAL_COUNT: Self = Self::iana(171);
    /// `postPacketTotalCount`
    pub const POST_PACKET_TOTAL_COUNT: Self = Self::iana(172);
    /// `flowKeyIndicator`
    pub const FLOW_KEY_INDICATOR: Self = Self::iana(173);
    /// `postMCastPacketTotalCount`
    pub const POST_MCAST_PACKET_TOTAL_COUNT: Self = Self::iana(174);
    /// `postMCastOctetTotalCount`
    pub const POST_MCAST_OCTET_TOTAL_COUNT: Self = Self::iana(175);
    /// `icmpTypeIPv4`
    pub const ICMP_TYPE_IPV4: Self = Self::iana(176);
    /// `icmpCodeIPv4`
    pub const ICMP_CODE_IPV4: Self = Self::iana(177);
    /// `icmpTypeIPv6`
    pub const ICMP_TYPE_IPV6: Self = Self::iana(178);
    /// `icmpCodeIPv6`
    pub const ICMP_CODE_IPV6: Self = Self::iana(179);
    /// `udpSourcePort`
    pub const UDP_SOURCE_PORT: Self = Self::iana(180);
    /// `udpDestinationPort`
    pub const UDP_DESTINATION_PORT: Self = Self::iana(181);
    /// `tcpSourcePort`
    pub const TCP_SOURCE_PORT: Self = Self::iana(182);
    /// `tcpDestinationPort`
    pub const TCP_DESTINATION_PORT: Self = Self::iana(183);
    /// `tcpSequenceNumber`
    pub const TCP_SEQUENCE_NUMBER: Self = Self::iana(184);
    /// `tcpAcknowledgementNumber`
    pub const TCP_ACKNOWLEDGEMENT_NUMBER: Self = Self::iana(185);
    /// `tcpWindowSize`
    pub const TCP_WINDOW_SIZE: Self = Self::iana(186);
    /// `tcpUrgentPointer`
    pub const TCP_URGENT_POINTER: Self = Self::iana(187);
    /// `tcpHeaderLength`
    pub const TCP_HEADER_LENGTH: Self = Self::iana(188);
    /// `ipHeaderLength`
    pub const IP_HEADER_LENGTH: Self = Self::iana(189);
    /// `totalLengthIPv4`
    pub const TOTAL_LENGTH_IPV4: Self = Self::iana(190);
    /// `payloadLengthIPv6`
    pub const PAYLOAD_LENGTH_IPV6: Self = Self::iana(191);
    /// `ipTTL`
    pub const IP_TTL: Self = Self::iana(192);
    /// `nextHeaderIPv6`
    pub const NEXT_HEADER_IPV6: Self = Self::iana(193);
    /// `mplsPayloadLength`
    pub const MPLS_PAYLOAD_LENGTH: Self = Self::iana(194);
    /// `ipDiffServCodePoint`
    pub const IP_DIFF_SERV_CODE_POINT: Self = Self::iana(195);
    /// `ipPrecedence`
    pub const IP_PRECEDENCE: Self = Self::iana(196);
    /// `fragmentFlags`
    pub const FRAGMENT_FLAGS: Self = Self::iana(197);
    /// `octetDeltaSumOfSquares`
    pub const OCTET_DELTA_SUM_OF_SQUARES: Self = Self::iana(198);
    /// `octetTotalSumOfSquares`
    pub const OCTET_TOTAL_SUM_OF_SQUARES: Self = Self::iana(199);
    /// `mplsTopLabelTTL`
    pub const MPLS_TOP_LABEL_TTL: Self = Self::iana(200);
    /// `mplsLabelStackLength`
    pub const MPLS_LABEL_STACK_LENGTH: Self = Self::iana(201);
    /// `mplsLabelStackDepth`
    pub const MPLS_LABEL_STACK_DEPTH: Self = Self::iana(202);
    /// `mplsTopLabelExp`
    pub const MPLS_TOP_LABEL_EXP: Self = Self::iana(203);
    /// `ipPayloadLength`
    pub const IP_PAYLOAD_LENGTH: Self = Self::iana(204);
    /// `udpMessageLength`
    pub const UDP_MESSAGE_LENGTH: Self = Self::iana(205);
    /// `isMulticast`
    pub const IS_MULTICAST: Self = Self::iana(206);
    /// `ipv4IHL`
    pub const IPV4_IHL: Self = Self::iana(207);
    /// `ipv4Options`
    pub const IPV4_OPTIONS: Self = Self::iana(208);
    /// `tcpOptions`
    pub const TCP_OPTIONS: Self = Self::iana(209);
    /// `paddingOctets`
    pub const PADDING_OCTETS: Self = Self::iana(210);
    /// `collectorIPv4Address`
    pub const COLLECTOR_IPV4_ADDRESS: Self = Self::iana(211);
    /// `collectorIPv6Address`
    pub const COLLECTOR_IPV6_ADDRESS: Self = Self::iana(212);
    /// `exportInterface`
    pub const EXPORT_INTERFACE: Self = Self::iana(213);
    /// `exportProtocolVersion`
    pub const EXPORT_PROTOCOL_VERSION: Self = Self::iana(214);
    /// `exportTransportProtocol`
    pub const EXPORT_TRANSPORT_PROTOCOL: Self = Self::iana(215);
    /// `collectorTransportPort`
    pub const COLLECTOR_TRANSPORT_PORT: Self = Self::iana(216);
    /// `exporterTransportPort`
    pub const EXPORTER_TRANSPORT_PORT: Self = Self::iana(217);
    /// `tcpSynTotalCount`
    pub const TCP_SYN_TOTAL_COUNT: Self = Self::iana(218);
    /// `tcpFinTotalCount`
    pub const TCP_FIN_TOTAL_COUNT: Self = Self::iana(219);
    /// `tcpRstTotalCount`
    pub const TCP_RST_TOTAL_COUNT: Self = Self::iana(220);
    /// `tcpPshTotalCount`
    pub const TCP_PSH_TOTAL_COUNT: Self = Self::iana(221);
    /// `tcpAckTotalCount`
    pub const TCP_ACK_TOTAL_COUNT: Self = Self::iana(222);
    /// `tcpUrgTotalCount`
    pub const TCP_URG_TOTAL_COUNT: Self = Self::iana(223);
    /// `ipTotalLength`
    pub const IP_TOTAL_LENGTH: Self = Self::iana(224);
    /// `postNATSourceIPv4Address`
    pub const POST_NAT_SOURCE_IPV4_ADDRESS: Self = Self::iana(225);
    /// `postNATDestinationIPv4Address`
    pub const POST_NAT_DESTINATION_IPV4_ADDRESS: Self = Self::iana(226);
    /// `postNAPTSourceTransportPort`
    pub const POST_NAPT_SOURCE_TRANSPORT_PORT: Self = Self::iana(227);
    /// `postNAPTDestinationTransportPort`
    pub const POST_NAPT_DESTINATION_TRANSPORT_PORT: Self = Self::iana(228);
    /// `natOriginatingAddressRealm`
    pub const NAT_ORIGINATING_ADDRESS_REALM: Self = Self::iana(229);
    /// `natEvent`
    pub const NAT_EVENT: Self = Self::iana(230);
    /// `initiatorOctets`
    pub const INITIATOR_OCTETS: Self = Self::iana(231);
    /// `responderOctets`
    pub const RESPONDER_OCTETS: Self = Self::iana(232);
    /// `firewallEvent`
    pub const FIREWALL_EVENT: Self = Self::iana(233);
    /// `ingressVRFID`
    pub const INGRESS_VRFID: Self = Self::iana(234);
    /// `egressVRFID`
    pub const EGRESS_VRFID: Self = Self::iana(235);
    /// `VRFname`
    pub const VRF_NAME: Self = Self::iana(236);
    /// `postMplsTopLabelExp`
    pub const POST_MPLS_TOP_LABEL_EXP: Self = Self::iana(237);
    /// `tcpWindowScale`
    pub const TCP_WINDOW_SCALE: Self = Self::iana(238);
    /// `biflowDirection`
    pub const BIFLOW_DIRECTION: Self = Self::iana(239);
    /// `ethernetHeaderLength`
    pub const ETHERNET_HEADER_LENGTH: Self = Self::iana(240);
    /// `ethernetPayloadLength`
    pub const ETHERNET_PAYLOAD_LENGTH: Self = Self::iana(241);
    /// `ethernetTotalLength`
    pub const ETHERNET_TOTAL_LENGTH: Self = Self::iana(242);
    /// `dot1qVlanId`
    pub const DOT1Q_VLAN_ID: Self = Self::iana(243);
    /// `dot1qPriority`
    pub const DOT1Q_PRIORITY: Self = Self::iana(244);
    /// `dot1qCustomerVlanId`
    pub const DOT1Q_CUSTOMER_VLAN_ID: Self = Self::iana(245);
    /// `dot1qCustomerPriority`
    pub const DOT1Q_CUSTOMER_PRIORITY: Self = Self::iana(246);
    /// `metroEvcId`
    pub const METRO_EVC_ID: Self = Self::iana(247);
    /// `metroEvcType`
    pub const METRO_EVC_TYPE: Self = Self::iana(248);
    /// `pseudoWireId`
    pub const PSEUDO_WIRE_ID: Self = Self::iana(249);
    /// `pseudoWireType`
    pub const PSEUDO_WIRE_TYPE: Self = Self::iana(250);
    /// `pseudoWireControlWord`
    pub const PSEUDO_WIRE_CONTROL_WORD: Self = Self::iana(251);
    /// `ingressPhysicalInterface`
    pub const INGRESS_PHYSICAL_INTERFACE: Self = Self::iana(252);
    /// `egressPhysicalInterface`
    pub const EGRESS_PHYSICAL_INTERFACE: Self = Self::iana(253);
    /// `postDot1qVlanId`
    pub const POST_DOT1Q_VLAN_ID: Self = Self::iana(254);
    /// `postDot1qCustomerVlanId`
    pub const POST_DOT1Q_CUSTOMER_VLAN_ID: Self = Self::iana(255);
    /// `ethernetType`
    pub const ETHERNET_TYPE: Self = Self::iana(256);
    /// `postIpPrecedence`
    pub const POST_IP_PRECEDENCE: Self = Self::iana(257);
    /// `collectionTimeMilliseconds`
    pub const COLLECTION_TIME_MILLISECONDS: Self = Self::iana(258);
    /// `exportSctpStreamId`
    pub const EXPORT_SCTP_STREAM_ID: Self = Self::iana(259);
    /// `maxExportSeconds`
    pub const MAX_EXPORT_SECONDS: Self = Self::iana(260);
    /// `maxFlowEndSeconds`
    pub const MAX_FLOW_END_SECONDS: Self = Self::iana(261);
    /// `messageMD5Checksum`
    pub const MESSAGE_MD5_CHECKSUM: Self = Self::iana(262);
    /// `messageScope`
    pub const MESSAGE_SCOPE: Self = Self::iana(263);
    /// `minExportSeconds`
    pub const MIN_EXPORT_SECONDS: Self = Self::iana(264);
    /// `minFlowStartSeconds`
    pub const MIN_FLOW_START_SECONDS: Self = Self::iana(265);
    /// `opaqueOctets`
    pub const OPAQUE_OCTETS: Self = Self::iana(266);
    /// `sessionScope`
    pub const SESSION_SCOPE: Self = Self::iana(267);
    /// `maxFlowEndMicroseconds`
    pub const MAX_FLOW_END_MICROSECONDS: Self = Self::iana(268);
    /// `maxFlowEndMilliseconds`
    pub const MAX_FLOW_END_MILLISECONDS: Self = Self::iana(269);
    /// `maxFlowEndNanoseconds`
    pub const MAX_FLOW_END_NANOSECONDS: Self = Self::iana(270);
    /// `minFlowStartMicroseconds`
    pub const MIN_FLOW_START_MICROSECONDS: Self = Self::iana(271);
    /// `minFlowStartMilliseconds`
    pub const MIN_FLOW_START_MILLISECONDS: Self = Self::iana(272);
    /// `minFlowStartNanoseconds`
    pub const MIN_FLOW_START_NANOSECONDS: Self = Self::iana(273);
    /// `collectorCertificate`
    pub const COLLECTOR_CERTIFICATE: Self = Self::iana(274);
    /// `exporterCertificate`
    pub const EXPORTER_CERTIFICATE: Self = Self::iana(275);
    /// `dataRecordsReliability`
    pub const DATA_RECORDS_RELIABILITY: Self = Self::iana(276);
    /// `observationPointType`
    pub const OBSERVATION_POINT_TYPE: Self = Self::iana(277);
    /// `newConnectionDeltaCount`
    pub const NEW_CONNECTION_DELTA_COUNT: Self = Self::iana(278);
    /// `connectionSumDurationSeconds`
    pub const CONNECTION_SUM_DURATION_SECONDS: Self = Self::iana(279);
    /// `connectionTransactionId`
    pub const CONNECTION_TRANSACTION_ID: Self = Self::iana(280);
    /// `postNATSourceIPv6Address`
    pub const POST_NAT_SOURCE_IPV6_ADDRESS: Self = Self::iana(281);
    /// `postNATDestinationIPv6Address`
    pub const POST_NAT_DESTINATION_IPV6_ADDRESS: Self = Self::iana(282);
    /// `natPoolId`
    pub const NAT_POOL_ID: Self = Self::iana(283);
    /// `natPoolName`
    pub const NAT_POOL_NAME: Self = Self::iana(284);
    /// `anonymizationFlags`
    pub const ANONYMIZATION_FLAGS: Self = Self::iana(285);
    /// `anonymizationTechnique`
    pub const ANONYMIZATION_TECHNIQUE: Self = Self::iana(286);
    /// `informationElementIndex`
    pub const INFORMATION_ELEMENT_INDEX: Self = Self::iana(287);
    /// `p2pTechnology`
    pub const P2P_TECHNOLOGY: Self = Self::iana(288);
    /// `tunnelTechnology`
    pub const TUNNEL_TECHNOLOGY: Self = Self::iana(289);
    /// `encryptedTechnology`
    pub const ENCRYPTED_TECHNOLOGY: Self = Self::iana(290);
    /// `basicList`
    pub const BASIC_LIST: Self = Self::iana(291);
    /// `subTemplateList`
    pub const SUB_TEMPLATE_LIST: Self = Self::iana(292);
    /// `subTemplateMultiList`
    pub const SUB_TEMPLATE_MULTI_LIST: Self = Self::iana(293);
    /// `bgpValidityState`
    pub const BGP_VALIDITY_STATE: Self = Self::iana(294);
    /// `IPSecSPI`
    pub const IPSEC_SPI: Self = Self::iana(295);
    /// `greKey`
    pub const GRE_KEY: Self = Self::iana(296);
    /// `natType`
    pub const NAT_TYPE: Self = Self::iana(297);
    /// `initiatorPackets`
    pub const INITIATOR_PACKETS: Self = Self::iana(298);
    /// `responderPackets`
    pub const RESPONDER_PACKETS: Self = Self::iana(299);
    /// `observationDomainName`
    pub const OBSERVATION_DOMAIN_NAME: Self = Self::iana(300);
    /// `selectionSequenceId`
    pub const SELECTION_SEQUENCE_ID: Self = Self::iana(301);
    /// `selectorId`
    pub const SELECTOR_ID: Self = Self::iana(302);
    /// `informationElementId`
    pub const INFORMATION_ELEMENT_ID: Self = Self::iana(303);
    /// `selectorAlgorithm`
    pub const SELECTOR_ALGORITHM: Self = Self::iana(304);
    /// `samplingPacketInterval`
    pub const SAMPLING_PACKET_INTERVAL: Self = Self::iana(305);
    /// `samplingPacketSpace`
    pub const SAMPLING_PACKET_SPACE: Self = Self::iana(306);
    /// `samplingTimeInterval`
    pub const SAMPLING_TIME_INTERVAL: Self = Self::iana(307);
    /// `samplingTimeSpace`
    pub const SAMPLING_TIME_SPACE: Self = Self::iana(308);
    /// `samplingSize`
    pub const SAMPLING_SIZE: Self = Self::iana(309);
    /// `samplingPopulation`
    pub const SAMPLING_POPULATION: Self = Self::iana(310);
    /// `samplingProbability`
    pub const SAMPLING_PROBABILITY: Self = Self::iana(311);
    /// `dataLinkFrameSize`
    pub const DATA_LINK_FRAME_SIZE: Self = Self::iana(312);
    /// `ipHeaderPacketSection`
    pub const IP_HEADER_PACKET_SECTION: Self = Self::iana(313);
    /// `ipPayloadPacketSection`
    pub const IP_PAYLOAD_PACKET_SECTION: Self = Self::iana(314);
    /// `dataLinkFrameSection`
    pub const DATA_LINK_FRAME_SECTION: Self = Self::iana(315);
    /// `mplsLabelStackSection`
    pub const MPLS_LABEL_STACK_SECTION: Self = Self::iana(316);
    /// `mplsPayloadPacketSection`
    pub const MPLS_PAYLOAD_PACKET_SECTION: Self = Self::iana(317);
    /// `selectorIdTotalPktsObserved`
    pub const SELECTOR_ID_TOTAL_PKTS_OBSERVED: Self = Self::iana(318);
    /// `selectorIdTotalPktsSelected`
    pub const SELECTOR_ID_TOTAL_PKTS_SELECTED: Self = Self::iana(319);
    /// `absoluteError`
    pub const ABSOLUTE_ERROR: Self = Self::iana(320);
    /// `relativeError`
    pub const RELATIVE_ERROR: Self = Self::iana(321);
    /// `observationTimeSeconds`
    pub const OBSERVATION_TIME_SECONDS: Self = Self::iana(322);
    /// `observationTimeMilliseconds`
    pub const OBSERVATION_TIME_MILLISECONDS: Self = Self::iana(323);
    /// `observationTimeMicroseconds`
    pub const OBSERVATION_TIME_MICROSECONDS: Self = Self::iana(324);
    /// `observationTimeNanoseconds`
    pub const OBSERVATION_TIME_NANOSECONDS: Self = Self::iana(325);
    /// `digestHashValue`
    pub const DIGEST_HASH_VALUE: Self = Self::iana(326);
    /// `hashIPPayloadOffset`
    pub const HASH_IP_PAYLOAD_OFFSET: Self = Self::iana(327);
    /// `hashIPPayloadSize`
    pub const HASH_IP_PAYLOAD_SIZE: Self = Self::iana(328);
    /// `hashOutputRangeMin`
    pub const HASH_OUTPUT_RANGE_MIN: Self = Self::iana(329);
    /// `hashOutputRangeMax`
    pub const HASH_OUTPUT_RANGE_MAX: Self = Self::iana(330);
    /// `hashSelectedRangeMin`
    pub const HASH_SELECTED_RANGE_MIN: Self = Self::iana(331);
    /// `hashSelectedRangeMax`
    pub const HASH_SELECTED_RANGE_MAX: Self = Self::iana(332);
    /// `hashDigestOutput`
    pub const HASH_DIGEST_OUTPUT: Self = Self::iana(333);
    /// `hashInitialiserValue`
    pub const HASH_INITIALISER_VALUE: Self = Self::iana(334);
    /// `selectorName`
    pub const SELECTOR_NAME: Self = Self::iana(335);
    /// `upperCILimit`
    pub const UPPER_CI_LIMIT: Self = Self::iana(336);
    /// `lowerCILimit`
    pub const LOWER_CI_LIMIT: Self = Self::iana(337);
    /// `confidenceLevel`
    pub const CONFIDENCE_LEVEL: Self = Self::iana(338);
    /// `informationElementDataType`
    pub const INFORMATION_ELEMENT_DATA_TYPE: Self = Self::iana(339);
    /// `informationElementDescription`
    pub const INFORMATION_ELEMENT_DESCRIPTION: Self = Self::iana(340);
    /// `informationElementName`
    pub const INFORMATION_ELEMENT_NAME: Self = Self::iana(341);
    /// `informationElementRangeBegin`
    pub const INFORMATION_ELEMENT_RANGE_BEGIN: Self = Self::iana(342);
    /// `informationElementRangeEnd`
    pub const INFORMATION_ELEMENT_RANGE_END: Self = Self::iana(343);
    /// `informationElementSemantics`
    pub const INFORMATION_ELEMENT_SEMANTICS: Self = Self::iana(344);
    /// `informationElementUnits`
    pub const INFORMATION_ELEMENT_UNITS: Self = Self::iana(345);
    /// `privateEnterpriseNumber`
    pub const PRIVATE_ENTERPRISE_NUMBER: Self = Self::iana(346);
    /// `virtualStationInterfaceId`
    pub const VIRTUAL_STATION_INTERFACE_ID: Self = Self::iana(347);
    /// `virtualStationInterfaceName`
    pub const VIRTUAL_STATION_INTERFACE_NAME: Self = Self::iana(348);
    /// `virtualStationUUID`
    pub const VIRTUAL_STATION_UUID: Self = Self::iana(349);
    /// `virtualStationName`
    pub const VIRTUAL_STATION_NAME: Self = Self::iana(350);
    /// `layer2SegmentId`
    pub const LAYER2_SEGMENT_ID: Self = Self::iana(351);
    /// `layer2OctetDeltaCount`
    pub const LAYER2_OCTET_DELTA_COUNT: Self = Self::iana(352);
    /// `layer2OctetTotalCount`
    pub const LAYER2_OCTET_TOTAL_COUNT: Self = Self::iana(353);
    /// `ingressUnicastPacketTotalCount`
    pub const INGRESS_UNICAST_PACKET_TOTAL_COUNT: Self = Self::iana(354);
    /// `ingressMulticastPacketTotalCount`
    pub const INGRESS_MULTICAST_PACKET_TOTAL_COUNT: Self = Self::iana(355);
    /// `ingressBroadcastPacketTotalCount`
    pub const INGRESS_BROADCAST_PACKET_TOTAL_COUNT: Self = Self::iana(356);
    /// `egressUnicastPacketTotalCount`
    pub const EGRESS_UNICAST_PACKET_TOTAL_COUNT: Self = Self::iana(357);
    /// `egressBroadcastPacketTotalCount`
    pub const EGRESS_BROADCAST_PACKET_TOTAL_COUNT: Self = Self::iana(358);
    /// `monitoringIntervalStartMilliSeconds`
    pub const MONITORING_INTERVAL_START_MILLI_SECONDS: Self = Self::iana(359);
    /// `monitoringIntervalEndMilliSeconds`
    pub const MONITORING_INTERVAL_END_MILLI_SECONDS: Self = Self::iana(360);
    /// `portRangeStart`
    pub const PORT_RANGE_START: Self = Self::iana(361);
    /// `portRangeEnd`
    pub const PORT_RANGE_END: Self = Self::iana(362);
    /// `portRangeStepSize`
    pub const PORT_RANGE_STEP_SIZE: Self = Self::iana(363);
    /// `portRangeNumPorts`
    pub const PORT_RANGE_NUM_PORTS: Self = Self::iana(364);
    /// `staMacAddress`
    pub const STA_MAC_ADDRESS: Self = Self::iana(365);
    /// `staIPv4Address`
    pub const STA_IPV4_ADDRESS: Self = Self::iana(366);
    /// `wtpMacAddress`
    pub const WTP_MAC_ADDRESS: Self = Self::iana(367);
    /// `ingressInterfaceType`
    pub const INGRESS_INTERFACE_TYPE: Self = Self::iana(368);
    /// `egressInterfaceType`
    pub const EGRESS_INTERFACE_TYPE: Self = Self::iana(369);
    /// `rtpSequenceNumber`
    pub const RTP_SEQUENCE_NUMBER: Self = Self::iana(370);
    /// `userName`
    pub const USER_NAME: Self = Self::iana(371);
    /// `applicationCategoryName`
    pub const APPLICATION_CATEGORY_NAME: Self = Self::iana(372);
    /// `applicationSubCategoryName`
    pub const APPLICATION_SUB_CATEGORY_NAME: Self = Self::iana(373);
    /// `applicationGroupName`
    pub const APPLICATION_GROUP_NAME: Self = Self::iana(374);
    /// `originalFlowsPresent`
    pub const ORIGINAL_FLOWS_PRESENT: Self = Self::iana(375);
    /// `originalFlowsInitiated`
    pub const ORIGINAL_FLOWS_INITIATED: Self = Self::iana(376);
    /// `originalFlowsCompleted`
    pub const ORIGINAL_FLOWS_COMPLETED: Self = Self::iana(377);
    /// `distinctCountOfSourceIPAddress`
    pub const DISTINCT_COUNT_OF_SOURCE_IP_ADDRESS: Self = Self::iana(378);
    /// `distinctCountOfDestinationIPAddress`
    pub const DISTINCT_COUNT_OF_DESTINATION_IP_ADDRESS: Self = Self::iana(379);
    /// `distinctCountOfSourceIPv4Address`
    pub const DISTINCT_COUNT_OF_SOURCE_IPV4_ADDRESS: Self = Self::iana(380);
    /// `distinctCountOfDestinationIPv4Address`
    pub const DISTINCT_COUNT_OF_DESTINATION_IPV4_ADDRESS: Self = Self::iana(381);
    /// `distinctCountOfSourceIPv6Address`
    pub const DISTINCT_COUNT_OF_SOURCE_IPV6_ADDRESS: Self = Self::iana(382);
    /// `distinctCountOfDestinationIPv6Address`
    pub const DISTINCT_COUNT_OF_DESTINATION_IPV6_ADDRESS: Self = Self::iana(383);
    /// `valueDistributionMethod`
    pub const VALUE_DISTRIBUTION_METHOD: Self = Self::iana(384);
    /// `rfc3550JitterMilliseconds`
    pub const RFC3550_JITTER_MILLISECONDS: Self = Self::iana(385);
    /// `rfc3550JitterMicroseconds`
    pub const RFC3550_JITTER_MICROSECONDS: Self = Self::iana(386);
    /// `rfc3550JitterNanoseconds`
    pub const RFC3550_JITTER_NANOSECONDS: Self = Self::iana(387);
    /// `dot1qDEI`
    pub const DOT1Q_DEI: Self = Self::iana(388);
    /// `dot1qCustomerDEI`
    pub const DOT1Q_CUSTOMER_DEI: Self = Self::iana(389);
    /// `flowSelectorAlgorithm`
    pub const FLOW_SELECTOR_ALGORITHM: Self = Self::iana(390);
    /// `flowSelectedOctetDeltaCount`
    pub const FLOW_SELECTED_OCTET_DELTA_COUNT: Self = Self::iana(391);
    /// `flowSelectedPacketDeltaCount`
    pub const FLOW_SELECTED_PACKET_DELTA_COUNT: Self = Self::iana(392);
    /// `flowSelectedFlowDeltaCount`
    pub const FLOW_SELECTED_FLOW_DELTA_COUNT: Self = Self::iana(393);
    /// `selectorIDTotalFlowsObserved`
    pub const SELECTOR_ID_TOTAL_FLOWS_OBSERVED: Self = Self::iana(394);
    /// `selectorIDTotalFlowsSelected`
    pub const SELECTOR_ID_TOTAL_FLOWS_SELECTED: Self = Self::iana(395);
    /// `samplingFlowInterval`
    pub const SAMPLING_FLOW_INTERVAL: Self = Self::iana(396);
    /// `samplingFlowSpacing`
    pub const SAMPLING_FLOW_SPACING: Self = Self::iana(397);
    /// `flowSamplingTimeInterval`
    pub const FLOW_SAMPLING_TIME_INTERVAL: Self = Self::iana(398);
    /// `flowSamplingTimeSpacing`
    pub const FLOW_SAMPLING_TIME_SPACING: Self = Self::iana(399);
    /// `hashFlowDomain`
    pub const HASH_FLOW_DOMAIN: Self = Self::iana(400);
    /// `transportOctetDeltaCount`
    pub const TRANSPORT_OCTET_DELTA_COUNT: Self = Self::iana(401);
    /// `transportPacketDeltaCount`
    pub const TRANSPORT_PACKET_DELTA_COUNT: Self = Self::iana(402);
    /// `originalExporterIPv4Address`
    pub const ORIGINAL_EXPORTER_IPV4_ADDRESS: Self = Self::iana(403);
    /// `originalExporterIPv6Address`
    pub const ORIGINAL_EXPORTER_IPV6_ADDRESS: Self = Self::iana(404);
    /// `originalObservationDomainId`
    pub const ORIGINAL_OBSERVATION_DOMAIN_ID: Self = Self::iana(405);
    /// `intermediateProcessId`
    pub const INTERMEDIATE_PROCESS_ID: Self = Self::iana(406);
    /// `ignoredDataRecordTotalCount`
    pub const IGNORED_DATA_RECORD_TOTAL_COUNT: Self = Self::iana(407);
    /// `dataLinkFrameType`
    pub const DATA_LINK_FRAME_TYPE: Self = Self::iana(408);
    /// `sectionOffset`
    pub const SECTION_OFFSET: Self = Self::iana(409);
    /// `sectionExportedOctets`
    pub const SECTION_EXPORTED_OCTETS: Self = Self::iana(410);
    /// `dot1qServiceInstanceTag`
    pub const DOT1Q_SERVICE_INSTANCE_TAG: Self = Self::iana(411);
    /// `dot1qServiceInstanceId`
    pub const DOT1Q_SERVICE_INSTANCE_ID: Self = Self::iana(412);
    /// `dot1qServiceInstancePriority`
    pub const DOT1Q_SERVICE_INSTANCE_PRIORITY: Self = Self::iana(413);
    /// `dot1qCustomerSourceMacAddress`
    pub const DOT1Q_CUSTOMER_SOURCE_MAC_ADDRESS: Self = Self::iana(414);
    /// `dot1qCustomerDestinationMacAddress`
    pub const DOT1Q_CUSTOMER_DESTINATION_MAC_ADDRESS: Self = Self::iana(415);
    /// `postLayer2OctetDeltaCount`
    pub const POST_LAYER2_OCTET_DELTA_COUNT: Self = Self::iana(417);
    /// `postMCastLayer2OctetDeltaCount`
    pub const POST_MCAST_LAYER2_OCTET_DELTA_COUNT: Self = Self::iana(418);
    /// `postLayer2OctetTotalCount`
    pub const POST_LAYER2_OCTET_TOTAL_COUNT: Self = Self::iana(420);
    /// `postMCastLayer2OctetTotalCount`
    pub const POST_MCAST_LAYER2_OCTET_TOTAL_COUNT: Self = Self::iana(421);
    /// `minimumLayer2TotalLength`
    pub const MINIMUM_LAYER2_TOTAL_LENGTH: Self = Self::iana(422);
    /// `maximumLayer2TotalLength`
    pub const MAXIMUM_LAYER2_TOTAL_LENGTH: Self = Self::iana(423);
    /// `droppedLayer2OctetDeltaCount`
    pub const DROPPED_LAYER2_OCTET_DELTA_COUNT: Self = Self::iana(424);
    /// `droppedLayer2OctetTotalCount`
    pub const DROPPED_LAYER2_OCTET_TOTAL_COUNT: Self = Self::iana(425);
    /// `ignoredLayer2OctetTotalCount`
    pub const IGNORED_LAYER2_OCTET_TOTAL_COUNT: Self = Self::iana(426);
    /// `notSentLayer2OctetTotalCount`
    pub const NOT_SENT_LAYER2_OCTET_TOTAL_COUNT: Self = Self::iana(427);
    /// `layer2OctetDeltaSumOfSquares`
    pub const LAYER2_OCTET_DELTA_SUM_OF_SQUARES: Self = Self::iana(428);
    /// `layer2OctetTotalSumOfSquares`
    pub const LAYER2_OCTET_TOTAL_SUM_OF_SQUARES: Self = Self::iana(429);
    /// `layer2FrameDeltaCount`
    pub const LAYER2_FRAME_DELTA_COUNT: Self = Self::iana(430);
    /// `layer2FrameTotalCount`
    pub const LAYER2_FRAME_TOTAL_COUNT: Self = Self::iana(431);
    /// `pseudoWireDestinationIPv4Address`
    pub const PSEUDO_WIRE_DESTINATION_IPV4_ADDRESS: Self = Self::iana(432);
    /// `ignoredLayer2FrameTotalCount`
    pub const IGNORED_LAYER2_FRAME_TOTAL_COUNT: Self = Self::iana(433);
    /// `mibObjectValueInteger`
    pub const MIB_OBJECT_VALUE_INTEGER: Self = Self::iana(434);
    /// `mibObjectValueOctetString`
    pub const MIB_OBJECT_VALUE_OCTET_STRING: Self = Self::iana(435);
    /// `mibObjectValueOID`
    pub const MIB_OBJECT_VALUE_OID: Self = Self::iana(436);
    /// `mibObjectValueBits`
    pub const MIB_OBJECT_VALUE_BITS: Self = Self::iana(437);
    /// `mibObjectValueIPAddress`
    pub const MIB_OBJECT_VALUE_IP_ADDRESS: Self = Self::iana(438);
    /// `mibObjectValueCounter`
    pub const MIB_OBJECT_VALUE_COUNTER: Self = Self::iana(439);
    /// `mibObjectValueGauge`
    pub const MIB_OBJECT_VALUE_GAUGE: Self = Self::iana(440);
    /// `mibObjectValueTimeTicks`
    pub const MIB_OBJECT_VALUE_TIME_TICKS: Self = Self::iana(441);
    /// `mibObjectValueUnsigned`
    pub const MIB_OBJECT_VALUE_UNSIGNED: Self = Self::iana(442);
    /// `mibObjectValueTable`
    pub const MIB_OBJECT_VALUE_TABLE: Self = Self::iana(443);
    /// `mibObjectValueRow`
    pub const MIB_OBJECT_VALUE_ROW: Self = Self::iana(444);
    /// `mibObjectIdentifier`
    pub const MIB_OBJECT_IDENTIFIER: Self = Self::iana(445);
    /// `mibSubIdentifier`
    pub const MIB_SUB_IDENTIFIER: Self = Self::iana(446);
    /// `mibIndexIndicator`
    pub const MIB_INDEX_INDICATOR: Self = Self::iana(447);
    /// `mibCaptureTimeSemantics`
    pub const MIB_CAPTURE_TIME_SEMANTICS: Self = Self::iana(448);
    /// `mibContextEngineID`
    pub const MIB_CONTEXT_ENGINE_ID: Self = Self::iana(449);
    /// `mibContextName`
    pub const MIB_CONTEXT_NAME: Self = Self::iana(450);
    /// `mibObjectName`
    pub const MIB_OBJECT_NAME: Self = Self::iana(451);
    /// `mibObjectDescription`
    pub const MIB_OBJECT_DESCRIPTION: Self = Self::iana(452);
    /// `mibObjectSyntax`
    pub const MIB_OBJECT_SYNTAX: Self = Self::iana(453);
    /// `mibModuleName`
    pub const MIB_MODULE_NAME: Self = Self::iana(454);
    /// `mobileIMSI`
    pub const MOBILE_IMSI: Self = Self::iana(455);
    /// `mobileMSISDN`
    pub const MOBILE_MSISDN: Self = Self::iana(456);
    /// `httpStatusCode`
    pub const HTTP_STATUS_CODE: Self = Self::iana(457);
    /// `sourceTransportPortsLimit`
    pub const SOURCE_TRANSPORT_PORTS_LIMIT: Self = Self::iana(458);
    /// `httpRequestMethod`
    pub const HTTP_REQUEST_METHOD: Self = Self::iana(459);
    /// `httpRequestHost`
    pub const HTTP_REQUEST_HOST: Self = Self::iana(460);
    /// `httpRequestTarget`
    pub const HTTP_REQUEST_TARGET: Self = Self::iana(461);
    /// `httpMessageVersion`
    pub const HTTP_MESSAGE_VERSION: Self = Self::iana(462);
    /// `natInstanceID`
    pub const NAT_INSTANCE_ID: Self = Self::iana(463);
    /// `internalAddressRealm`
    pub const INTERNAL_ADDRESS_REALM: Self = Self::iana(464);
    /// `externalAddressRealm`
    pub const EXTERNAL_ADDRESS_REALM: Self = Self::iana(465);
    /// `natQuotaExceededEvent`
    pub const NAT_QUOTA_EXCEEDED_EVENT: Self = Self::iana(466);
    /// `natThresholdEvent`
    pub const NAT_THRESHOLD_EVENT: Self = Self::iana(467);
    /// `httpUserAgent`
    pub const HTTP_USER_AGENT: Self = Self::iana(468);
    /// `httpContentType`
    pub const HTTP_CONTENT_TYPE: Self = Self::iana(469);
    /// `httpReasonPhrase`
    pub const HTTP_REASON_PHRASE: Self = Self::iana(470);
    /// `maxSessionEntries`
    pub const MAX_SESSION_ENTRIES: Self = Self::iana(471);
    /// `maxBIBEntries`
    pub const MAX_BIB_ENTRIES: Self = Self::iana(472);
    /// `maxEntriesPerUser`
    pub const MAX_ENTRIES_PER_USER: Self = Self::iana(473);
    /// `maxSubscribers`
    pub const MAX_SUBSCRIBERS: Self = Self::iana(474);
    /// `maxFragmentsPendingReassembly`
    pub const MAX_FRAGMENTS_PENDING_REASSEMBLY: Self = Self::iana(475);
    /// `addressPoolHighThreshold`
    pub const ADDRESS_POOL_HIGH_THRESHOLD: Self = Self::iana(476);
    /// `addressPoolLowThreshold`
    pub const ADDRESS_POOL_LOW_THRESHOLD: Self = Self::iana(477);
    /// `addressPortMappingHighThreshold`
    pub const ADDRESS_PORT_MAPPING_HIGH_THRESHOLD: Self = Self::iana(478);
    /// `addressPortMappingLowThreshold`
    pub const ADDRESS_PORT_MAPPING_LOW_THRESHOLD: Self = Self::iana(479);
    /// `addressPortMappingPerUserHighThreshold`
    pub const ADDRESS_PORT_MAPPING_PER_USER_HIGH_THRESHOLD: Self = Self::iana(480);
    /// `globalAddressMappingHighThreshold`
    pub const GLOBAL_ADDRESS_MAPPING_HIGH_THRESHOLD: Self = Self::iana(481);
    /// `vpnIdentifier`
    pub const VPN_IDENTIFIER: Self = Self::iana(482);
    /// `bgpCommunity`
    pub const BGP_COMMUNITY: Self = Self::iana(483);
    /// `bgpSourceCommunityList`
    pub const BGP_SOURCE_COMMUNITY_LIST: Self = Self::iana(484);
    /// `bgpDestinationCommunityList`
    pub const BGP_DESTINATION_COMMUNITY_LIST: Self = Self::iana(485);
    /// `bgpExtendedCommunity`
    pub const BGP_EXTENDED_COMMUNITY: Self = Self::iana(486);
    /// `bgpSourceExtendedCommunityList`
    pub const BGP_SOURCE_EXTENDED_COMMUNITY_LIST: Self = Self::iana(487);
    /// `bgpDestinationExtendedCommunityList`
    pub const BGP_DESTINATION_EXTENDED_COMMUNITY_LIST: Self = Self::iana(488);
    /// `bgpLargeCommunity`
    pub const BGP_LARGE_COMMUNITY: Self = Self::iana(489);
    /// `bgpSourceLargeCommunityList`
    pub const BGP_SOURCE_LARGE_COMMUNITY_LIST: Self = Self::iana(490);
    /// `bgpDestinationLargeCommunityList`
    pub const BGP_DESTINATION_LARGE_COMMUNITY_LIST: Self = Self::iana(491);
    /// `srhFlagsIPv6`
    pub const SRH_FLAGS_IPV6: Self = Self::iana(492);
    /// `srhTagIPv6`
    pub const SRH_TAG_IPV6: Self = Self::iana(493);
    /// `srhSegmentIPv6`
    pub const SRH_SEGMENT_IPV6: Self = Self::iana(494);
    /// `srhActiveSegmentIPv6`
    pub const SRH_ACTIVE_SEGMENT_IPV6: Self = Self::iana(495);
    /// `srhSegmentIPv6BasicList`
    pub const SRH_SEGMENT_IPV6_BASIC_LIST: Self = Self::iana(496);
    /// `srhSegmentIPv6ListSection`
    pub const SRH_SEGMENT_IPV6_LIST_SECTION: Self = Self::iana(497);
    /// `srhSegmentsIPv6Left`
    pub const SRH_SEGMENTS_IPV6_LEFT: Self = Self::iana(498);
    /// `srhIPv6Section`
    pub const SRH_IPV6_SECTION: Self = Self::iana(499);
    /// `srhIPv6ActiveSegmentType`
    pub const SRH_IPV6_ACTIVE_SEGMENT_TYPE: Self = Self::iana(500);
    /// `srhSegmentIPv6LocatorLength`
    pub const SRH_SEGMENT_IPV6_LOCATOR_LENGTH: Self = Self::iana(501);
    /// `srhSegmentIPv6EndpointBehavior`
    pub const SRH_SEGMENT_IPV6_ENDPOINT_BEHAVIOR: Self = Self::iana(502);
    /// `transportChecksum`
    pub const TRANSPORT_CHECKSUM: Self = Self::iana(503);
    /// `icmpHeaderPacketSection`
    pub const ICMP_HEADER_PACKET_SECTION: Self = Self::iana(504);
    /// `gtpuFlags`
    pub const GTPU_FLAGS: Self = Self::iana(505);
    /// `gtpuMsgType`
    pub const GTPU_MSG_TYPE: Self = Self::iana(506);
    /// `gtpuTEid`
    pub const GTPU_TEID: Self = Self::iana(507);
    /// `gtpuSequenceNum`
    pub const GTPU_SEQUENCE_NUM: Self = Self::iana(508);
    /// `gtpuQFI`
    pub const GTPU_QFI: Self = Self::iana(509);
    /// `gtpuPduType`
    pub const GTPU_PDU_TYPE: Self = Self::iana(510);
    /// `bgpSourceAsPathList`
    pub const BGP_SOURCE_AS_PATH_LIST: Self = Self::iana(511);
    /// `bgpDestinationAsPathList`
    pub const BGP_DESTINATION_AS_PATH_LIST: Self = Self::iana(512);
    /// `ipv6ExtensionHeaderType`
    pub const IPV6_EXTENSION_HEADER_TYPE: Self = Self::iana(513);
    /// `ipv6ExtensionHeaderCount`
    pub const IPV6_EXTENSION_HEADER_COUNT: Self = Self::iana(514);
    /// `ipv6ExtensionHeadersFull`
    pub const IPV6_EXTENSION_HEADERS_FULL: Self = Self::iana(515);
    /// `ipv6ExtensionHeaderTypeCountList`
    pub const IPV6_EXTENSION_HEADER_TYPE_COUNT_LIST: Self = Self::iana(516);
    /// `ipv6ExtensionHeadersLimit`
    pub const IPV6_EXTENSION_HEADERS_LIMIT: Self = Self::iana(517);
    /// `ipv6ExtensionHeadersChainLength`
    pub const IPV6_EXTENSION_HEADERS_CHAIN_LENGTH: Self = Self::iana(518);
    /// `ipv6ExtensionHeaderChainLengthList`
    pub const IPV6_EXTENSION_HEADER_CHAIN_LENGTH_LIST: Self = Self::iana(519);
    /// `tcpOptionsFull`
    pub const TCP_OPTIONS_FULL: Self = Self::iana(520);
    /// `tcpSharedOptionExID16`
    pub const TCP_SHARED_OPTION_EX_ID16: Self = Self::iana(521);
    /// `tcpSharedOptionExID32`
    pub const TCP_SHARED_OPTION_EX_ID32: Self = Self::iana(522);
    /// `tcpSharedOptionExID16List`
    pub const TCP_SHARED_OPTION_EX_ID16_LIST: Self = Self::iana(523);
    /// `tcpSharedOptionExID32List`
    pub const TCP_SHARED_OPTION_EX_ID32_LIST: Self = Self::iana(524);
    /// `udpSafeOptions`
    pub const UDP_SAFE_OPTIONS: Self = Self::iana(525);
    /// `udpUnsafeOptions`
    pub const UDP_UNSAFE_OPTIONS: Self = Self::iana(526);
    /// `udpExID`
    pub const UDP_EX_ID: Self = Self::iana(527);
    /// `udpSafeExIDList`
    pub const UDP_SAFE_EX_ID_LIST: Self = Self::iana(528);
    /// `udpUnsafeExIDList`
    pub const UDP_UNSAFE_EX_ID_LIST: Self = Self::iana(529);
    /// `pathDelayMeanDeltaMicroseconds`
    pub const PATH_DELAY_MEAN_DELTA_MICROSECONDS: Self = Self::iana(530);
    /// `pathDelayMinDeltaMicroseconds`
    pub const PATH_DELAY_MIN_DELTA_MICROSECONDS: Self = Self::iana(531);
    /// `pathDelayMaxDeltaMicroseconds`
    pub const PATH_DELAY_MAX_DELTA_MICROSECONDS: Self = Self::iana(532);
    /// `pathDelaySumDeltaMicroseconds`
    pub const PATH_DELAY_SUM_DELTA_MICROSECONDS: Self = Self::iana(533);
}
