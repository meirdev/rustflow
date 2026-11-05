//! IANA's IPFIX Information Elements registry, generated from
//! <https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv>
//! as last updated 2026-04-02. Entries without an abstract data type
//! (reserved and unassigned IDs, and the deprecated duplicates 416 and 419)
//! are left out.

use super::DataType::{self, *};
use super::DataTypeSemantics::{self, *};
use super::ElementId;

#[rustfmt::skip]
pub(crate) const ELEMENTS: &[(u16, &str, DataType, Option<DataTypeSemantics>)] = &[
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

/// `octetDeltaCount`
pub const OCTET_DELTA_COUNT: ElementId = ElementId::iana(1);

/// `packetDeltaCount`
pub const PACKET_DELTA_COUNT: ElementId = ElementId::iana(2);

/// `deltaFlowCount`
pub const DELTA_FLOW_COUNT: ElementId = ElementId::iana(3);

/// `protocolIdentifier`
pub const PROTOCOL_IDENTIFIER: ElementId = ElementId::iana(4);

/// `ipClassOfService`
pub const IP_CLASS_OF_SERVICE: ElementId = ElementId::iana(5);

/// `tcpControlBits`
pub const TCP_CONTROL_BITS: ElementId = ElementId::iana(6);

/// `sourceTransportPort`
pub const SOURCE_TRANSPORT_PORT: ElementId = ElementId::iana(7);

/// `sourceIPv4Address`
pub const SOURCE_IPV4_ADDRESS: ElementId = ElementId::iana(8);

/// `sourceIPv4PrefixLength`
pub const SOURCE_IPV4_PREFIX_LENGTH: ElementId = ElementId::iana(9);

/// `ingressInterface`
pub const INGRESS_INTERFACE: ElementId = ElementId::iana(10);

/// `destinationTransportPort`
pub const DESTINATION_TRANSPORT_PORT: ElementId = ElementId::iana(11);

/// `destinationIPv4Address`
pub const DESTINATION_IPV4_ADDRESS: ElementId = ElementId::iana(12);

/// `destinationIPv4PrefixLength`
pub const DESTINATION_IPV4_PREFIX_LENGTH: ElementId = ElementId::iana(13);

/// `egressInterface`
pub const EGRESS_INTERFACE: ElementId = ElementId::iana(14);

/// `ipNextHopIPv4Address`
pub const IP_NEXT_HOP_IPV4_ADDRESS: ElementId = ElementId::iana(15);

/// `bgpSourceAsNumber`
pub const BGP_SOURCE_AS_NUMBER: ElementId = ElementId::iana(16);

/// `bgpDestinationAsNumber`
pub const BGP_DESTINATION_AS_NUMBER: ElementId = ElementId::iana(17);

/// `bgpNextHopIPv4Address`
pub const BGP_NEXT_HOP_IPV4_ADDRESS: ElementId = ElementId::iana(18);

/// `postMCastPacketDeltaCount`
pub const POST_M_CAST_PACKET_DELTA_COUNT: ElementId = ElementId::iana(19);

/// `postMCastOctetDeltaCount`
pub const POST_M_CAST_OCTET_DELTA_COUNT: ElementId = ElementId::iana(20);

/// `flowEndSysUpTime`
pub const FLOW_END_SYS_UP_TIME: ElementId = ElementId::iana(21);

/// `flowStartSysUpTime`
pub const FLOW_START_SYS_UP_TIME: ElementId = ElementId::iana(22);

/// `postOctetDeltaCount`
pub const POST_OCTET_DELTA_COUNT: ElementId = ElementId::iana(23);

/// `postPacketDeltaCount`
pub const POST_PACKET_DELTA_COUNT: ElementId = ElementId::iana(24);

/// `minimumIpTotalLength`
pub const MINIMUM_IP_TOTAL_LENGTH: ElementId = ElementId::iana(25);

/// `maximumIpTotalLength`
pub const MAXIMUM_IP_TOTAL_LENGTH: ElementId = ElementId::iana(26);

/// `sourceIPv6Address`
pub const SOURCE_IPV6_ADDRESS: ElementId = ElementId::iana(27);

/// `destinationIPv6Address`
pub const DESTINATION_IPV6_ADDRESS: ElementId = ElementId::iana(28);

/// `sourceIPv6PrefixLength`
pub const SOURCE_IPV6_PREFIX_LENGTH: ElementId = ElementId::iana(29);

/// `destinationIPv6PrefixLength`
pub const DESTINATION_IPV6_PREFIX_LENGTH: ElementId = ElementId::iana(30);

/// `flowLabelIPv6`
pub const FLOW_LABEL_IPV6: ElementId = ElementId::iana(31);

/// `icmpTypeCodeIPv4`
pub const ICMP_TYPE_CODE_IPV4: ElementId = ElementId::iana(32);

/// `igmpType`
pub const IGMP_TYPE: ElementId = ElementId::iana(33);

/// `samplingInterval`
pub const SAMPLING_INTERVAL: ElementId = ElementId::iana(34);

/// `samplingAlgorithm`
pub const SAMPLING_ALGORITHM: ElementId = ElementId::iana(35);

/// `flowActiveTimeout`
pub const FLOW_ACTIVE_TIMEOUT: ElementId = ElementId::iana(36);

/// `flowIdleTimeout`
pub const FLOW_IDLE_TIMEOUT: ElementId = ElementId::iana(37);

/// `engineType`
pub const ENGINE_TYPE: ElementId = ElementId::iana(38);

/// `engineId`
pub const ENGINE_ID: ElementId = ElementId::iana(39);

/// `exportedOctetTotalCount`
pub const EXPORTED_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(40);

/// `exportedMessageTotalCount`
pub const EXPORTED_MESSAGE_TOTAL_COUNT: ElementId = ElementId::iana(41);

/// `exportedFlowRecordTotalCount`
pub const EXPORTED_FLOW_RECORD_TOTAL_COUNT: ElementId = ElementId::iana(42);

/// `ipv4RouterSc`
pub const IPV4_ROUTER_SC: ElementId = ElementId::iana(43);

/// `sourceIPv4Prefix`
pub const SOURCE_IPV4_PREFIX: ElementId = ElementId::iana(44);

/// `destinationIPv4Prefix`
pub const DESTINATION_IPV4_PREFIX: ElementId = ElementId::iana(45);

/// `mplsTopLabelType`
pub const MPLS_TOP_LABEL_TYPE: ElementId = ElementId::iana(46);

/// `mplsTopLabelIPv4Address`
pub const MPLS_TOP_LABEL_IPV4_ADDRESS: ElementId = ElementId::iana(47);

/// `samplerId`
pub const SAMPLER_ID: ElementId = ElementId::iana(48);

/// `samplerMode`
pub const SAMPLER_MODE: ElementId = ElementId::iana(49);

/// `samplerRandomInterval`
pub const SAMPLER_RANDOM_INTERVAL: ElementId = ElementId::iana(50);

/// `classId`
pub const CLASS_ID: ElementId = ElementId::iana(51);

/// `minimumTTL`
pub const MINIMUM_TTL: ElementId = ElementId::iana(52);

/// `maximumTTL`
pub const MAXIMUM_TTL: ElementId = ElementId::iana(53);

/// `fragmentIdentification`
pub const FRAGMENT_IDENTIFICATION: ElementId = ElementId::iana(54);

/// `postIpClassOfService`
pub const POST_IP_CLASS_OF_SERVICE: ElementId = ElementId::iana(55);

/// `sourceMacAddress`
pub const SOURCE_MAC_ADDRESS: ElementId = ElementId::iana(56);

/// `postDestinationMacAddress`
pub const POST_DESTINATION_MAC_ADDRESS: ElementId = ElementId::iana(57);

/// `vlanId`
pub const VLAN_ID: ElementId = ElementId::iana(58);

/// `postVlanId`
pub const POST_VLAN_ID: ElementId = ElementId::iana(59);

/// `ipVersion`
pub const IP_VERSION: ElementId = ElementId::iana(60);

/// `flowDirection`
pub const FLOW_DIRECTION: ElementId = ElementId::iana(61);

/// `ipNextHopIPv6Address`
pub const IP_NEXT_HOP_IPV6_ADDRESS: ElementId = ElementId::iana(62);

/// `bgpNextHopIPv6Address`
pub const BGP_NEXT_HOP_IPV6_ADDRESS: ElementId = ElementId::iana(63);

/// `ipv6ExtensionHeaders`
pub const IPV6_EXTENSION_HEADERS: ElementId = ElementId::iana(64);

/// `mplsTopLabelStackSection`
pub const MPLS_TOP_LABEL_STACK_SECTION: ElementId = ElementId::iana(70);

/// `mplsLabelStackSection2`
pub const MPLS_LABEL_STACK_SECTION2: ElementId = ElementId::iana(71);

/// `mplsLabelStackSection3`
pub const MPLS_LABEL_STACK_SECTION3: ElementId = ElementId::iana(72);

/// `mplsLabelStackSection4`
pub const MPLS_LABEL_STACK_SECTION4: ElementId = ElementId::iana(73);

/// `mplsLabelStackSection5`
pub const MPLS_LABEL_STACK_SECTION5: ElementId = ElementId::iana(74);

/// `mplsLabelStackSection6`
pub const MPLS_LABEL_STACK_SECTION6: ElementId = ElementId::iana(75);

/// `mplsLabelStackSection7`
pub const MPLS_LABEL_STACK_SECTION7: ElementId = ElementId::iana(76);

/// `mplsLabelStackSection8`
pub const MPLS_LABEL_STACK_SECTION8: ElementId = ElementId::iana(77);

/// `mplsLabelStackSection9`
pub const MPLS_LABEL_STACK_SECTION9: ElementId = ElementId::iana(78);

/// `mplsLabelStackSection10`
pub const MPLS_LABEL_STACK_SECTION10: ElementId = ElementId::iana(79);

/// `destinationMacAddress`
pub const DESTINATION_MAC_ADDRESS: ElementId = ElementId::iana(80);

/// `postSourceMacAddress`
pub const POST_SOURCE_MAC_ADDRESS: ElementId = ElementId::iana(81);

/// `interfaceName`
pub const INTERFACE_NAME: ElementId = ElementId::iana(82);

/// `interfaceDescription`
pub const INTERFACE_DESCRIPTION: ElementId = ElementId::iana(83);

/// `samplerName`
pub const SAMPLER_NAME: ElementId = ElementId::iana(84);

/// `octetTotalCount`
pub const OCTET_TOTAL_COUNT: ElementId = ElementId::iana(85);

/// `packetTotalCount`
pub const PACKET_TOTAL_COUNT: ElementId = ElementId::iana(86);

/// `flagsAndSamplerId`
pub const FLAGS_AND_SAMPLER_ID: ElementId = ElementId::iana(87);

/// `fragmentOffset`
pub const FRAGMENT_OFFSET: ElementId = ElementId::iana(88);

/// `forwardingStatus`
pub const FORWARDING_STATUS: ElementId = ElementId::iana(89);

/// `mplsVpnRouteDistinguisher`
pub const MPLS_VPN_ROUTE_DISTINGUISHER: ElementId = ElementId::iana(90);

/// `mplsTopLabelPrefixLength`
pub const MPLS_TOP_LABEL_PREFIX_LENGTH: ElementId = ElementId::iana(91);

/// `srcTrafficIndex`
pub const SRC_TRAFFIC_INDEX: ElementId = ElementId::iana(92);

/// `dstTrafficIndex`
pub const DST_TRAFFIC_INDEX: ElementId = ElementId::iana(93);

/// `applicationDescription`
pub const APPLICATION_DESCRIPTION: ElementId = ElementId::iana(94);

/// `applicationId`
pub const APPLICATION_ID: ElementId = ElementId::iana(95);

/// `applicationName`
pub const APPLICATION_NAME: ElementId = ElementId::iana(96);

/// `postIpDiffServCodePoint`
pub const POST_IP_DIFF_SERV_CODE_POINT: ElementId = ElementId::iana(98);

/// `multicastReplicationFactor`
pub const MULTICAST_REPLICATION_FACTOR: ElementId = ElementId::iana(99);

/// `className`
pub const CLASS_NAME: ElementId = ElementId::iana(100);

/// `classificationEngineId`
pub const CLASSIFICATION_ENGINE_ID: ElementId = ElementId::iana(101);

/// `layer2packetSectionOffset`
pub const LAYER2PACKET_SECTION_OFFSET: ElementId = ElementId::iana(102);

/// `layer2packetSectionSize`
pub const LAYER2PACKET_SECTION_SIZE: ElementId = ElementId::iana(103);

/// `layer2packetSectionData`
pub const LAYER2PACKET_SECTION_DATA: ElementId = ElementId::iana(104);

/// `bgpNextAdjacentAsNumber`
pub const BGP_NEXT_ADJACENT_AS_NUMBER: ElementId = ElementId::iana(128);

/// `bgpPrevAdjacentAsNumber`
pub const BGP_PREV_ADJACENT_AS_NUMBER: ElementId = ElementId::iana(129);

/// `exporterIPv4Address`
pub const EXPORTER_IPV4_ADDRESS: ElementId = ElementId::iana(130);

/// `exporterIPv6Address`
pub const EXPORTER_IPV6_ADDRESS: ElementId = ElementId::iana(131);

/// `droppedOctetDeltaCount`
pub const DROPPED_OCTET_DELTA_COUNT: ElementId = ElementId::iana(132);

/// `droppedPacketDeltaCount`
pub const DROPPED_PACKET_DELTA_COUNT: ElementId = ElementId::iana(133);

/// `droppedOctetTotalCount`
pub const DROPPED_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(134);

/// `droppedPacketTotalCount`
pub const DROPPED_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(135);

/// `flowEndReason`
pub const FLOW_END_REASON: ElementId = ElementId::iana(136);

/// `commonPropertiesId`
pub const COMMON_PROPERTIES_ID: ElementId = ElementId::iana(137);

/// `observationPointId`
pub const OBSERVATION_POINT_ID: ElementId = ElementId::iana(138);

/// `icmpTypeCodeIPv6`
pub const ICMP_TYPE_CODE_IPV6: ElementId = ElementId::iana(139);

/// `mplsTopLabelIPv6Address`
pub const MPLS_TOP_LABEL_IPV6_ADDRESS: ElementId = ElementId::iana(140);

/// `lineCardId`
pub const LINE_CARD_ID: ElementId = ElementId::iana(141);

/// `portId`
pub const PORT_ID: ElementId = ElementId::iana(142);

/// `meteringProcessId`
pub const METERING_PROCESS_ID: ElementId = ElementId::iana(143);

/// `exportingProcessId`
pub const EXPORTING_PROCESS_ID: ElementId = ElementId::iana(144);

/// `templateId`
pub const TEMPLATE_ID: ElementId = ElementId::iana(145);

/// `wlanChannelId`
pub const WLAN_CHANNEL_ID: ElementId = ElementId::iana(146);

/// `wlanSSID`
pub const WLAN_SSID: ElementId = ElementId::iana(147);

/// `flowId`
pub const FLOW_ID: ElementId = ElementId::iana(148);

/// `observationDomainId`
pub const OBSERVATION_DOMAIN_ID: ElementId = ElementId::iana(149);

/// `flowStartSeconds`
pub const FLOW_START_SECONDS: ElementId = ElementId::iana(150);

/// `flowEndSeconds`
pub const FLOW_END_SECONDS: ElementId = ElementId::iana(151);

/// `flowStartMilliseconds`
pub const FLOW_START_MILLISECONDS: ElementId = ElementId::iana(152);

/// `flowEndMilliseconds`
pub const FLOW_END_MILLISECONDS: ElementId = ElementId::iana(153);

/// `flowStartMicroseconds`
pub const FLOW_START_MICROSECONDS: ElementId = ElementId::iana(154);

/// `flowEndMicroseconds`
pub const FLOW_END_MICROSECONDS: ElementId = ElementId::iana(155);

/// `flowStartNanoseconds`
pub const FLOW_START_NANOSECONDS: ElementId = ElementId::iana(156);

/// `flowEndNanoseconds`
pub const FLOW_END_NANOSECONDS: ElementId = ElementId::iana(157);

/// `flowStartDeltaMicroseconds`
pub const FLOW_START_DELTA_MICROSECONDS: ElementId = ElementId::iana(158);

/// `flowEndDeltaMicroseconds`
pub const FLOW_END_DELTA_MICROSECONDS: ElementId = ElementId::iana(159);

/// `systemInitTimeMilliseconds`
pub const SYSTEM_INIT_TIME_MILLISECONDS: ElementId = ElementId::iana(160);

/// `flowDurationMilliseconds`
pub const FLOW_DURATION_MILLISECONDS: ElementId = ElementId::iana(161);

/// `flowDurationMicroseconds`
pub const FLOW_DURATION_MICROSECONDS: ElementId = ElementId::iana(162);

/// `observedFlowTotalCount`
pub const OBSERVED_FLOW_TOTAL_COUNT: ElementId = ElementId::iana(163);

/// `ignoredPacketTotalCount`
pub const IGNORED_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(164);

/// `ignoredOctetTotalCount`
pub const IGNORED_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(165);

/// `notSentFlowTotalCount`
pub const NOT_SENT_FLOW_TOTAL_COUNT: ElementId = ElementId::iana(166);

/// `notSentPacketTotalCount`
pub const NOT_SENT_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(167);

/// `notSentOctetTotalCount`
pub const NOT_SENT_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(168);

/// `destinationIPv6Prefix`
pub const DESTINATION_IPV6_PREFIX: ElementId = ElementId::iana(169);

/// `sourceIPv6Prefix`
pub const SOURCE_IPV6_PREFIX: ElementId = ElementId::iana(170);

/// `postOctetTotalCount`
pub const POST_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(171);

/// `postPacketTotalCount`
pub const POST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(172);

/// `flowKeyIndicator`
pub const FLOW_KEY_INDICATOR: ElementId = ElementId::iana(173);

/// `postMCastPacketTotalCount`
pub const POST_M_CAST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(174);

/// `postMCastOctetTotalCount`
pub const POST_M_CAST_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(175);

/// `icmpTypeIPv4`
pub const ICMP_TYPE_IPV4: ElementId = ElementId::iana(176);

/// `icmpCodeIPv4`
pub const ICMP_CODE_IPV4: ElementId = ElementId::iana(177);

/// `icmpTypeIPv6`
pub const ICMP_TYPE_IPV6: ElementId = ElementId::iana(178);

/// `icmpCodeIPv6`
pub const ICMP_CODE_IPV6: ElementId = ElementId::iana(179);

/// `udpSourcePort`
pub const UDP_SOURCE_PORT: ElementId = ElementId::iana(180);

/// `udpDestinationPort`
pub const UDP_DESTINATION_PORT: ElementId = ElementId::iana(181);

/// `tcpSourcePort`
pub const TCP_SOURCE_PORT: ElementId = ElementId::iana(182);

/// `tcpDestinationPort`
pub const TCP_DESTINATION_PORT: ElementId = ElementId::iana(183);

/// `tcpSequenceNumber`
pub const TCP_SEQUENCE_NUMBER: ElementId = ElementId::iana(184);

/// `tcpAcknowledgementNumber`
pub const TCP_ACKNOWLEDGEMENT_NUMBER: ElementId = ElementId::iana(185);

/// `tcpWindowSize`
pub const TCP_WINDOW_SIZE: ElementId = ElementId::iana(186);

/// `tcpUrgentPointer`
pub const TCP_URGENT_POINTER: ElementId = ElementId::iana(187);

/// `tcpHeaderLength`
pub const TCP_HEADER_LENGTH: ElementId = ElementId::iana(188);

/// `ipHeaderLength`
pub const IP_HEADER_LENGTH: ElementId = ElementId::iana(189);

/// `totalLengthIPv4`
pub const TOTAL_LENGTH_IPV4: ElementId = ElementId::iana(190);

/// `payloadLengthIPv6`
pub const PAYLOAD_LENGTH_IPV6: ElementId = ElementId::iana(191);

/// `ipTTL`
pub const IP_TTL: ElementId = ElementId::iana(192);

/// `nextHeaderIPv6`
pub const NEXT_HEADER_IPV6: ElementId = ElementId::iana(193);

/// `mplsPayloadLength`
pub const MPLS_PAYLOAD_LENGTH: ElementId = ElementId::iana(194);

/// `ipDiffServCodePoint`
pub const IP_DIFF_SERV_CODE_POINT: ElementId = ElementId::iana(195);

/// `ipPrecedence`
pub const IP_PRECEDENCE: ElementId = ElementId::iana(196);

/// `fragmentFlags`
pub const FRAGMENT_FLAGS: ElementId = ElementId::iana(197);

/// `octetDeltaSumOfSquares`
pub const OCTET_DELTA_SUM_OF_SQUARES: ElementId = ElementId::iana(198);

/// `octetTotalSumOfSquares`
pub const OCTET_TOTAL_SUM_OF_SQUARES: ElementId = ElementId::iana(199);

/// `mplsTopLabelTTL`
pub const MPLS_TOP_LABEL_TTL: ElementId = ElementId::iana(200);

/// `mplsLabelStackLength`
pub const MPLS_LABEL_STACK_LENGTH: ElementId = ElementId::iana(201);

/// `mplsLabelStackDepth`
pub const MPLS_LABEL_STACK_DEPTH: ElementId = ElementId::iana(202);

/// `mplsTopLabelExp`
pub const MPLS_TOP_LABEL_EXP: ElementId = ElementId::iana(203);

/// `ipPayloadLength`
pub const IP_PAYLOAD_LENGTH: ElementId = ElementId::iana(204);

/// `udpMessageLength`
pub const UDP_MESSAGE_LENGTH: ElementId = ElementId::iana(205);

/// `isMulticast`
pub const IS_MULTICAST: ElementId = ElementId::iana(206);

/// `ipv4IHL`
pub const IPV4_IHL: ElementId = ElementId::iana(207);

/// `ipv4Options`
pub const IPV4_OPTIONS: ElementId = ElementId::iana(208);

/// `tcpOptions`
pub const TCP_OPTIONS: ElementId = ElementId::iana(209);

/// `paddingOctets`
pub const PADDING_OCTETS: ElementId = ElementId::iana(210);

/// `collectorIPv4Address`
pub const COLLECTOR_IPV4_ADDRESS: ElementId = ElementId::iana(211);

/// `collectorIPv6Address`
pub const COLLECTOR_IPV6_ADDRESS: ElementId = ElementId::iana(212);

/// `exportInterface`
pub const EXPORT_INTERFACE: ElementId = ElementId::iana(213);

/// `exportProtocolVersion`
pub const EXPORT_PROTOCOL_VERSION: ElementId = ElementId::iana(214);

/// `exportTransportProtocol`
pub const EXPORT_TRANSPORT_PROTOCOL: ElementId = ElementId::iana(215);

/// `collectorTransportPort`
pub const COLLECTOR_TRANSPORT_PORT: ElementId = ElementId::iana(216);

/// `exporterTransportPort`
pub const EXPORTER_TRANSPORT_PORT: ElementId = ElementId::iana(217);

/// `tcpSynTotalCount`
pub const TCP_SYN_TOTAL_COUNT: ElementId = ElementId::iana(218);

/// `tcpFinTotalCount`
pub const TCP_FIN_TOTAL_COUNT: ElementId = ElementId::iana(219);

/// `tcpRstTotalCount`
pub const TCP_RST_TOTAL_COUNT: ElementId = ElementId::iana(220);

/// `tcpPshTotalCount`
pub const TCP_PSH_TOTAL_COUNT: ElementId = ElementId::iana(221);

/// `tcpAckTotalCount`
pub const TCP_ACK_TOTAL_COUNT: ElementId = ElementId::iana(222);

/// `tcpUrgTotalCount`
pub const TCP_URG_TOTAL_COUNT: ElementId = ElementId::iana(223);

/// `ipTotalLength`
pub const IP_TOTAL_LENGTH: ElementId = ElementId::iana(224);

/// `postNATSourceIPv4Address`
pub const POST_NAT_SOURCE_IPV4_ADDRESS: ElementId = ElementId::iana(225);

/// `postNATDestinationIPv4Address`
pub const POST_NAT_DESTINATION_IPV4_ADDRESS: ElementId = ElementId::iana(226);

/// `postNAPTSourceTransportPort`
pub const POST_NAPT_SOURCE_TRANSPORT_PORT: ElementId = ElementId::iana(227);

/// `postNAPTDestinationTransportPort`
pub const POST_NAPT_DESTINATION_TRANSPORT_PORT: ElementId = ElementId::iana(228);

/// `natOriginatingAddressRealm`
pub const NAT_ORIGINATING_ADDRESS_REALM: ElementId = ElementId::iana(229);

/// `natEvent`
pub const NAT_EVENT: ElementId = ElementId::iana(230);

/// `initiatorOctets`
pub const INITIATOR_OCTETS: ElementId = ElementId::iana(231);

/// `responderOctets`
pub const RESPONDER_OCTETS: ElementId = ElementId::iana(232);

/// `firewallEvent`
pub const FIREWALL_EVENT: ElementId = ElementId::iana(233);

/// `ingressVRFID`
pub const INGRESS_VRFID: ElementId = ElementId::iana(234);

/// `egressVRFID`
pub const EGRESS_VRFID: ElementId = ElementId::iana(235);

/// `VRFname`
pub const VR_FNAME: ElementId = ElementId::iana(236);

/// `postMplsTopLabelExp`
pub const POST_MPLS_TOP_LABEL_EXP: ElementId = ElementId::iana(237);

/// `tcpWindowScale`
pub const TCP_WINDOW_SCALE: ElementId = ElementId::iana(238);

/// `biflowDirection`
pub const BIFLOW_DIRECTION: ElementId = ElementId::iana(239);

/// `ethernetHeaderLength`
pub const ETHERNET_HEADER_LENGTH: ElementId = ElementId::iana(240);

/// `ethernetPayloadLength`
pub const ETHERNET_PAYLOAD_LENGTH: ElementId = ElementId::iana(241);

/// `ethernetTotalLength`
pub const ETHERNET_TOTAL_LENGTH: ElementId = ElementId::iana(242);

/// `dot1qVlanId`
pub const DOT1Q_VLAN_ID: ElementId = ElementId::iana(243);

/// `dot1qPriority`
pub const DOT1Q_PRIORITY: ElementId = ElementId::iana(244);

/// `dot1qCustomerVlanId`
pub const DOT1Q_CUSTOMER_VLAN_ID: ElementId = ElementId::iana(245);

/// `dot1qCustomerPriority`
pub const DOT1Q_CUSTOMER_PRIORITY: ElementId = ElementId::iana(246);

/// `metroEvcId`
pub const METRO_EVC_ID: ElementId = ElementId::iana(247);

/// `metroEvcType`
pub const METRO_EVC_TYPE: ElementId = ElementId::iana(248);

/// `pseudoWireId`
pub const PSEUDO_WIRE_ID: ElementId = ElementId::iana(249);

/// `pseudoWireType`
pub const PSEUDO_WIRE_TYPE: ElementId = ElementId::iana(250);

/// `pseudoWireControlWord`
pub const PSEUDO_WIRE_CONTROL_WORD: ElementId = ElementId::iana(251);

/// `ingressPhysicalInterface`
pub const INGRESS_PHYSICAL_INTERFACE: ElementId = ElementId::iana(252);

/// `egressPhysicalInterface`
pub const EGRESS_PHYSICAL_INTERFACE: ElementId = ElementId::iana(253);

/// `postDot1qVlanId`
pub const POST_DOT1Q_VLAN_ID: ElementId = ElementId::iana(254);

/// `postDot1qCustomerVlanId`
pub const POST_DOT1Q_CUSTOMER_VLAN_ID: ElementId = ElementId::iana(255);

/// `ethernetType`
pub const ETHERNET_TYPE: ElementId = ElementId::iana(256);

/// `postIpPrecedence`
pub const POST_IP_PRECEDENCE: ElementId = ElementId::iana(257);

/// `collectionTimeMilliseconds`
pub const COLLECTION_TIME_MILLISECONDS: ElementId = ElementId::iana(258);

/// `exportSctpStreamId`
pub const EXPORT_SCTP_STREAM_ID: ElementId = ElementId::iana(259);

/// `maxExportSeconds`
pub const MAX_EXPORT_SECONDS: ElementId = ElementId::iana(260);

/// `maxFlowEndSeconds`
pub const MAX_FLOW_END_SECONDS: ElementId = ElementId::iana(261);

/// `messageMD5Checksum`
pub const MESSAGE_MD5_CHECKSUM: ElementId = ElementId::iana(262);

/// `messageScope`
pub const MESSAGE_SCOPE: ElementId = ElementId::iana(263);

/// `minExportSeconds`
pub const MIN_EXPORT_SECONDS: ElementId = ElementId::iana(264);

/// `minFlowStartSeconds`
pub const MIN_FLOW_START_SECONDS: ElementId = ElementId::iana(265);

/// `opaqueOctets`
pub const OPAQUE_OCTETS: ElementId = ElementId::iana(266);

/// `sessionScope`
pub const SESSION_SCOPE: ElementId = ElementId::iana(267);

/// `maxFlowEndMicroseconds`
pub const MAX_FLOW_END_MICROSECONDS: ElementId = ElementId::iana(268);

/// `maxFlowEndMilliseconds`
pub const MAX_FLOW_END_MILLISECONDS: ElementId = ElementId::iana(269);

/// `maxFlowEndNanoseconds`
pub const MAX_FLOW_END_NANOSECONDS: ElementId = ElementId::iana(270);

/// `minFlowStartMicroseconds`
pub const MIN_FLOW_START_MICROSECONDS: ElementId = ElementId::iana(271);

/// `minFlowStartMilliseconds`
pub const MIN_FLOW_START_MILLISECONDS: ElementId = ElementId::iana(272);

/// `minFlowStartNanoseconds`
pub const MIN_FLOW_START_NANOSECONDS: ElementId = ElementId::iana(273);

/// `collectorCertificate`
pub const COLLECTOR_CERTIFICATE: ElementId = ElementId::iana(274);

/// `exporterCertificate`
pub const EXPORTER_CERTIFICATE: ElementId = ElementId::iana(275);

/// `dataRecordsReliability`
pub const DATA_RECORDS_RELIABILITY: ElementId = ElementId::iana(276);

/// `observationPointType`
pub const OBSERVATION_POINT_TYPE: ElementId = ElementId::iana(277);

/// `newConnectionDeltaCount`
pub const NEW_CONNECTION_DELTA_COUNT: ElementId = ElementId::iana(278);

/// `connectionSumDurationSeconds`
pub const CONNECTION_SUM_DURATION_SECONDS: ElementId = ElementId::iana(279);

/// `connectionTransactionId`
pub const CONNECTION_TRANSACTION_ID: ElementId = ElementId::iana(280);

/// `postNATSourceIPv6Address`
pub const POST_NAT_SOURCE_IPV6_ADDRESS: ElementId = ElementId::iana(281);

/// `postNATDestinationIPv6Address`
pub const POST_NAT_DESTINATION_IPV6_ADDRESS: ElementId = ElementId::iana(282);

/// `natPoolId`
pub const NAT_POOL_ID: ElementId = ElementId::iana(283);

/// `natPoolName`
pub const NAT_POOL_NAME: ElementId = ElementId::iana(284);

/// `anonymizationFlags`
pub const ANONYMIZATION_FLAGS: ElementId = ElementId::iana(285);

/// `anonymizationTechnique`
pub const ANONYMIZATION_TECHNIQUE: ElementId = ElementId::iana(286);

/// `informationElementIndex`
pub const INFORMATION_ELEMENT_INDEX: ElementId = ElementId::iana(287);

/// `p2pTechnology`
pub const P2P_TECHNOLOGY: ElementId = ElementId::iana(288);

/// `tunnelTechnology`
pub const TUNNEL_TECHNOLOGY: ElementId = ElementId::iana(289);

/// `encryptedTechnology`
pub const ENCRYPTED_TECHNOLOGY: ElementId = ElementId::iana(290);

/// `basicList`
pub const BASIC_LIST: ElementId = ElementId::iana(291);

/// `subTemplateList`
pub const SUB_TEMPLATE_LIST: ElementId = ElementId::iana(292);

/// `subTemplateMultiList`
pub const SUB_TEMPLATE_MULTI_LIST: ElementId = ElementId::iana(293);

/// `bgpValidityState`
pub const BGP_VALIDITY_STATE: ElementId = ElementId::iana(294);

/// `IPSecSPI`
pub const IP_SEC_SPI: ElementId = ElementId::iana(295);

/// `greKey`
pub const GRE_KEY: ElementId = ElementId::iana(296);

/// `natType`
pub const NAT_TYPE: ElementId = ElementId::iana(297);

/// `initiatorPackets`
pub const INITIATOR_PACKETS: ElementId = ElementId::iana(298);

/// `responderPackets`
pub const RESPONDER_PACKETS: ElementId = ElementId::iana(299);

/// `observationDomainName`
pub const OBSERVATION_DOMAIN_NAME: ElementId = ElementId::iana(300);

/// `selectionSequenceId`
pub const SELECTION_SEQUENCE_ID: ElementId = ElementId::iana(301);

/// `selectorId`
pub const SELECTOR_ID: ElementId = ElementId::iana(302);

/// `informationElementId`
pub const INFORMATION_ELEMENT_ID: ElementId = ElementId::iana(303);

/// `selectorAlgorithm`
pub const SELECTOR_ALGORITHM: ElementId = ElementId::iana(304);

/// `samplingPacketInterval`
pub const SAMPLING_PACKET_INTERVAL: ElementId = ElementId::iana(305);

/// `samplingPacketSpace`
pub const SAMPLING_PACKET_SPACE: ElementId = ElementId::iana(306);

/// `samplingTimeInterval`
pub const SAMPLING_TIME_INTERVAL: ElementId = ElementId::iana(307);

/// `samplingTimeSpace`
pub const SAMPLING_TIME_SPACE: ElementId = ElementId::iana(308);

/// `samplingSize`
pub const SAMPLING_SIZE: ElementId = ElementId::iana(309);

/// `samplingPopulation`
pub const SAMPLING_POPULATION: ElementId = ElementId::iana(310);

/// `samplingProbability`
pub const SAMPLING_PROBABILITY: ElementId = ElementId::iana(311);

/// `dataLinkFrameSize`
pub const DATA_LINK_FRAME_SIZE: ElementId = ElementId::iana(312);

/// `ipHeaderPacketSection`
pub const IP_HEADER_PACKET_SECTION: ElementId = ElementId::iana(313);

/// `ipPayloadPacketSection`
pub const IP_PAYLOAD_PACKET_SECTION: ElementId = ElementId::iana(314);

/// `dataLinkFrameSection`
pub const DATA_LINK_FRAME_SECTION: ElementId = ElementId::iana(315);

/// `mplsLabelStackSection`
pub const MPLS_LABEL_STACK_SECTION: ElementId = ElementId::iana(316);

/// `mplsPayloadPacketSection`
pub const MPLS_PAYLOAD_PACKET_SECTION: ElementId = ElementId::iana(317);

/// `selectorIdTotalPktsObserved`
pub const SELECTOR_ID_TOTAL_PKTS_OBSERVED: ElementId = ElementId::iana(318);

/// `selectorIdTotalPktsSelected`
pub const SELECTOR_ID_TOTAL_PKTS_SELECTED: ElementId = ElementId::iana(319);

/// `absoluteError`
pub const ABSOLUTE_ERROR: ElementId = ElementId::iana(320);

/// `relativeError`
pub const RELATIVE_ERROR: ElementId = ElementId::iana(321);

/// `observationTimeSeconds`
pub const OBSERVATION_TIME_SECONDS: ElementId = ElementId::iana(322);

/// `observationTimeMilliseconds`
pub const OBSERVATION_TIME_MILLISECONDS: ElementId = ElementId::iana(323);

/// `observationTimeMicroseconds`
pub const OBSERVATION_TIME_MICROSECONDS: ElementId = ElementId::iana(324);

/// `observationTimeNanoseconds`
pub const OBSERVATION_TIME_NANOSECONDS: ElementId = ElementId::iana(325);

/// `digestHashValue`
pub const DIGEST_HASH_VALUE: ElementId = ElementId::iana(326);

/// `hashIPPayloadOffset`
pub const HASH_IP_PAYLOAD_OFFSET: ElementId = ElementId::iana(327);

/// `hashIPPayloadSize`
pub const HASH_IP_PAYLOAD_SIZE: ElementId = ElementId::iana(328);

/// `hashOutputRangeMin`
pub const HASH_OUTPUT_RANGE_MIN: ElementId = ElementId::iana(329);

/// `hashOutputRangeMax`
pub const HASH_OUTPUT_RANGE_MAX: ElementId = ElementId::iana(330);

/// `hashSelectedRangeMin`
pub const HASH_SELECTED_RANGE_MIN: ElementId = ElementId::iana(331);

/// `hashSelectedRangeMax`
pub const HASH_SELECTED_RANGE_MAX: ElementId = ElementId::iana(332);

/// `hashDigestOutput`
pub const HASH_DIGEST_OUTPUT: ElementId = ElementId::iana(333);

/// `hashInitialiserValue`
pub const HASH_INITIALISER_VALUE: ElementId = ElementId::iana(334);

/// `selectorName`
pub const SELECTOR_NAME: ElementId = ElementId::iana(335);

/// `upperCILimit`
pub const UPPER_CI_LIMIT: ElementId = ElementId::iana(336);

/// `lowerCILimit`
pub const LOWER_CI_LIMIT: ElementId = ElementId::iana(337);

/// `confidenceLevel`
pub const CONFIDENCE_LEVEL: ElementId = ElementId::iana(338);

/// `informationElementDataType`
pub const INFORMATION_ELEMENT_DATA_TYPE: ElementId = ElementId::iana(339);

/// `informationElementDescription`
pub const INFORMATION_ELEMENT_DESCRIPTION: ElementId = ElementId::iana(340);

/// `informationElementName`
pub const INFORMATION_ELEMENT_NAME: ElementId = ElementId::iana(341);

/// `informationElementRangeBegin`
pub const INFORMATION_ELEMENT_RANGE_BEGIN: ElementId = ElementId::iana(342);

/// `informationElementRangeEnd`
pub const INFORMATION_ELEMENT_RANGE_END: ElementId = ElementId::iana(343);

/// `informationElementSemantics`
pub const INFORMATION_ELEMENT_SEMANTICS: ElementId = ElementId::iana(344);

/// `informationElementUnits`
pub const INFORMATION_ELEMENT_UNITS: ElementId = ElementId::iana(345);

/// `privateEnterpriseNumber`
pub const PRIVATE_ENTERPRISE_NUMBER: ElementId = ElementId::iana(346);

/// `virtualStationInterfaceId`
pub const VIRTUAL_STATION_INTERFACE_ID: ElementId = ElementId::iana(347);

/// `virtualStationInterfaceName`
pub const VIRTUAL_STATION_INTERFACE_NAME: ElementId = ElementId::iana(348);

/// `virtualStationUUID`
pub const VIRTUAL_STATION_UUID: ElementId = ElementId::iana(349);

/// `virtualStationName`
pub const VIRTUAL_STATION_NAME: ElementId = ElementId::iana(350);

/// `layer2SegmentId`
pub const LAYER2_SEGMENT_ID: ElementId = ElementId::iana(351);

/// `layer2OctetDeltaCount`
pub const LAYER2_OCTET_DELTA_COUNT: ElementId = ElementId::iana(352);

/// `layer2OctetTotalCount`
pub const LAYER2_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(353);

/// `ingressUnicastPacketTotalCount`
pub const INGRESS_UNICAST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(354);

/// `ingressMulticastPacketTotalCount`
pub const INGRESS_MULTICAST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(355);

/// `ingressBroadcastPacketTotalCount`
pub const INGRESS_BROADCAST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(356);

/// `egressUnicastPacketTotalCount`
pub const EGRESS_UNICAST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(357);

/// `egressBroadcastPacketTotalCount`
pub const EGRESS_BROADCAST_PACKET_TOTAL_COUNT: ElementId = ElementId::iana(358);

/// `monitoringIntervalStartMilliSeconds`
pub const MONITORING_INTERVAL_START_MILLI_SECONDS: ElementId = ElementId::iana(359);

/// `monitoringIntervalEndMilliSeconds`
pub const MONITORING_INTERVAL_END_MILLI_SECONDS: ElementId = ElementId::iana(360);

/// `portRangeStart`
pub const PORT_RANGE_START: ElementId = ElementId::iana(361);

/// `portRangeEnd`
pub const PORT_RANGE_END: ElementId = ElementId::iana(362);

/// `portRangeStepSize`
pub const PORT_RANGE_STEP_SIZE: ElementId = ElementId::iana(363);

/// `portRangeNumPorts`
pub const PORT_RANGE_NUM_PORTS: ElementId = ElementId::iana(364);

/// `staMacAddress`
pub const STA_MAC_ADDRESS: ElementId = ElementId::iana(365);

/// `staIPv4Address`
pub const STA_IPV4_ADDRESS: ElementId = ElementId::iana(366);

/// `wtpMacAddress`
pub const WTP_MAC_ADDRESS: ElementId = ElementId::iana(367);

/// `ingressInterfaceType`
pub const INGRESS_INTERFACE_TYPE: ElementId = ElementId::iana(368);

/// `egressInterfaceType`
pub const EGRESS_INTERFACE_TYPE: ElementId = ElementId::iana(369);

/// `rtpSequenceNumber`
pub const RTP_SEQUENCE_NUMBER: ElementId = ElementId::iana(370);

/// `userName`
pub const USER_NAME: ElementId = ElementId::iana(371);

/// `applicationCategoryName`
pub const APPLICATION_CATEGORY_NAME: ElementId = ElementId::iana(372);

/// `applicationSubCategoryName`
pub const APPLICATION_SUB_CATEGORY_NAME: ElementId = ElementId::iana(373);

/// `applicationGroupName`
pub const APPLICATION_GROUP_NAME: ElementId = ElementId::iana(374);

/// `originalFlowsPresent`
pub const ORIGINAL_FLOWS_PRESENT: ElementId = ElementId::iana(375);

/// `originalFlowsInitiated`
pub const ORIGINAL_FLOWS_INITIATED: ElementId = ElementId::iana(376);

/// `originalFlowsCompleted`
pub const ORIGINAL_FLOWS_COMPLETED: ElementId = ElementId::iana(377);

/// `distinctCountOfSourceIPAddress`
pub const DISTINCT_COUNT_OF_SOURCE_IP_ADDRESS: ElementId = ElementId::iana(378);

/// `distinctCountOfDestinationIPAddress`
pub const DISTINCT_COUNT_OF_DESTINATION_IP_ADDRESS: ElementId = ElementId::iana(379);

/// `distinctCountOfSourceIPv4Address`
pub const DISTINCT_COUNT_OF_SOURCE_IPV4_ADDRESS: ElementId = ElementId::iana(380);

/// `distinctCountOfDestinationIPv4Address`
pub const DISTINCT_COUNT_OF_DESTINATION_IPV4_ADDRESS: ElementId = ElementId::iana(381);

/// `distinctCountOfSourceIPv6Address`
pub const DISTINCT_COUNT_OF_SOURCE_IPV6_ADDRESS: ElementId = ElementId::iana(382);

/// `distinctCountOfDestinationIPv6Address`
pub const DISTINCT_COUNT_OF_DESTINATION_IPV6_ADDRESS: ElementId = ElementId::iana(383);

/// `valueDistributionMethod`
pub const VALUE_DISTRIBUTION_METHOD: ElementId = ElementId::iana(384);

/// `rfc3550JitterMilliseconds`
pub const RFC3550_JITTER_MILLISECONDS: ElementId = ElementId::iana(385);

/// `rfc3550JitterMicroseconds`
pub const RFC3550_JITTER_MICROSECONDS: ElementId = ElementId::iana(386);

/// `rfc3550JitterNanoseconds`
pub const RFC3550_JITTER_NANOSECONDS: ElementId = ElementId::iana(387);

/// `dot1qDEI`
pub const DOT1Q_DEI: ElementId = ElementId::iana(388);

/// `dot1qCustomerDEI`
pub const DOT1Q_CUSTOMER_DEI: ElementId = ElementId::iana(389);

/// `flowSelectorAlgorithm`
pub const FLOW_SELECTOR_ALGORITHM: ElementId = ElementId::iana(390);

/// `flowSelectedOctetDeltaCount`
pub const FLOW_SELECTED_OCTET_DELTA_COUNT: ElementId = ElementId::iana(391);

/// `flowSelectedPacketDeltaCount`
pub const FLOW_SELECTED_PACKET_DELTA_COUNT: ElementId = ElementId::iana(392);

/// `flowSelectedFlowDeltaCount`
pub const FLOW_SELECTED_FLOW_DELTA_COUNT: ElementId = ElementId::iana(393);

/// `selectorIDTotalFlowsObserved`
pub const SELECTOR_ID_TOTAL_FLOWS_OBSERVED: ElementId = ElementId::iana(394);

/// `selectorIDTotalFlowsSelected`
pub const SELECTOR_ID_TOTAL_FLOWS_SELECTED: ElementId = ElementId::iana(395);

/// `samplingFlowInterval`
pub const SAMPLING_FLOW_INTERVAL: ElementId = ElementId::iana(396);

/// `samplingFlowSpacing`
pub const SAMPLING_FLOW_SPACING: ElementId = ElementId::iana(397);

/// `flowSamplingTimeInterval`
pub const FLOW_SAMPLING_TIME_INTERVAL: ElementId = ElementId::iana(398);

/// `flowSamplingTimeSpacing`
pub const FLOW_SAMPLING_TIME_SPACING: ElementId = ElementId::iana(399);

/// `hashFlowDomain`
pub const HASH_FLOW_DOMAIN: ElementId = ElementId::iana(400);

/// `transportOctetDeltaCount`
pub const TRANSPORT_OCTET_DELTA_COUNT: ElementId = ElementId::iana(401);

/// `transportPacketDeltaCount`
pub const TRANSPORT_PACKET_DELTA_COUNT: ElementId = ElementId::iana(402);

/// `originalExporterIPv4Address`
pub const ORIGINAL_EXPORTER_IPV4_ADDRESS: ElementId = ElementId::iana(403);

/// `originalExporterIPv6Address`
pub const ORIGINAL_EXPORTER_IPV6_ADDRESS: ElementId = ElementId::iana(404);

/// `originalObservationDomainId`
pub const ORIGINAL_OBSERVATION_DOMAIN_ID: ElementId = ElementId::iana(405);

/// `intermediateProcessId`
pub const INTERMEDIATE_PROCESS_ID: ElementId = ElementId::iana(406);

/// `ignoredDataRecordTotalCount`
pub const IGNORED_DATA_RECORD_TOTAL_COUNT: ElementId = ElementId::iana(407);

/// `dataLinkFrameType`
pub const DATA_LINK_FRAME_TYPE: ElementId = ElementId::iana(408);

/// `sectionOffset`
pub const SECTION_OFFSET: ElementId = ElementId::iana(409);

/// `sectionExportedOctets`
pub const SECTION_EXPORTED_OCTETS: ElementId = ElementId::iana(410);

/// `dot1qServiceInstanceTag`
pub const DOT1Q_SERVICE_INSTANCE_TAG: ElementId = ElementId::iana(411);

/// `dot1qServiceInstanceId`
pub const DOT1Q_SERVICE_INSTANCE_ID: ElementId = ElementId::iana(412);

/// `dot1qServiceInstancePriority`
pub const DOT1Q_SERVICE_INSTANCE_PRIORITY: ElementId = ElementId::iana(413);

/// `dot1qCustomerSourceMacAddress`
pub const DOT1Q_CUSTOMER_SOURCE_MAC_ADDRESS: ElementId = ElementId::iana(414);

/// `dot1qCustomerDestinationMacAddress`
pub const DOT1Q_CUSTOMER_DESTINATION_MAC_ADDRESS: ElementId = ElementId::iana(415);

/// `postLayer2OctetDeltaCount`
pub const POST_LAYER2_OCTET_DELTA_COUNT: ElementId = ElementId::iana(417);

/// `postMCastLayer2OctetDeltaCount`
pub const POST_M_CAST_LAYER2_OCTET_DELTA_COUNT: ElementId = ElementId::iana(418);

/// `postLayer2OctetTotalCount`
pub const POST_LAYER2_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(420);

/// `postMCastLayer2OctetTotalCount`
pub const POST_M_CAST_LAYER2_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(421);

/// `minimumLayer2TotalLength`
pub const MINIMUM_LAYER2_TOTAL_LENGTH: ElementId = ElementId::iana(422);

/// `maximumLayer2TotalLength`
pub const MAXIMUM_LAYER2_TOTAL_LENGTH: ElementId = ElementId::iana(423);

/// `droppedLayer2OctetDeltaCount`
pub const DROPPED_LAYER2_OCTET_DELTA_COUNT: ElementId = ElementId::iana(424);

/// `droppedLayer2OctetTotalCount`
pub const DROPPED_LAYER2_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(425);

/// `ignoredLayer2OctetTotalCount`
pub const IGNORED_LAYER2_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(426);

/// `notSentLayer2OctetTotalCount`
pub const NOT_SENT_LAYER2_OCTET_TOTAL_COUNT: ElementId = ElementId::iana(427);

/// `layer2OctetDeltaSumOfSquares`
pub const LAYER2_OCTET_DELTA_SUM_OF_SQUARES: ElementId = ElementId::iana(428);

/// `layer2OctetTotalSumOfSquares`
pub const LAYER2_OCTET_TOTAL_SUM_OF_SQUARES: ElementId = ElementId::iana(429);

/// `layer2FrameDeltaCount`
pub const LAYER2_FRAME_DELTA_COUNT: ElementId = ElementId::iana(430);

/// `layer2FrameTotalCount`
pub const LAYER2_FRAME_TOTAL_COUNT: ElementId = ElementId::iana(431);

/// `pseudoWireDestinationIPv4Address`
pub const PSEUDO_WIRE_DESTINATION_IPV4_ADDRESS: ElementId = ElementId::iana(432);

/// `ignoredLayer2FrameTotalCount`
pub const IGNORED_LAYER2_FRAME_TOTAL_COUNT: ElementId = ElementId::iana(433);

/// `mibObjectValueInteger`
pub const MIB_OBJECT_VALUE_INTEGER: ElementId = ElementId::iana(434);

/// `mibObjectValueOctetString`
pub const MIB_OBJECT_VALUE_OCTET_STRING: ElementId = ElementId::iana(435);

/// `mibObjectValueOID`
pub const MIB_OBJECT_VALUE_OID: ElementId = ElementId::iana(436);

/// `mibObjectValueBits`
pub const MIB_OBJECT_VALUE_BITS: ElementId = ElementId::iana(437);

/// `mibObjectValueIPAddress`
pub const MIB_OBJECT_VALUE_IP_ADDRESS: ElementId = ElementId::iana(438);

/// `mibObjectValueCounter`
pub const MIB_OBJECT_VALUE_COUNTER: ElementId = ElementId::iana(439);

/// `mibObjectValueGauge`
pub const MIB_OBJECT_VALUE_GAUGE: ElementId = ElementId::iana(440);

/// `mibObjectValueTimeTicks`
pub const MIB_OBJECT_VALUE_TIME_TICKS: ElementId = ElementId::iana(441);

/// `mibObjectValueUnsigned`
pub const MIB_OBJECT_VALUE_UNSIGNED: ElementId = ElementId::iana(442);

/// `mibObjectValueTable`
pub const MIB_OBJECT_VALUE_TABLE: ElementId = ElementId::iana(443);

/// `mibObjectValueRow`
pub const MIB_OBJECT_VALUE_ROW: ElementId = ElementId::iana(444);

/// `mibObjectIdentifier`
pub const MIB_OBJECT_IDENTIFIER: ElementId = ElementId::iana(445);

/// `mibSubIdentifier`
pub const MIB_SUB_IDENTIFIER: ElementId = ElementId::iana(446);

/// `mibIndexIndicator`
pub const MIB_INDEX_INDICATOR: ElementId = ElementId::iana(447);

/// `mibCaptureTimeSemantics`
pub const MIB_CAPTURE_TIME_SEMANTICS: ElementId = ElementId::iana(448);

/// `mibContextEngineID`
pub const MIB_CONTEXT_ENGINE_ID: ElementId = ElementId::iana(449);

/// `mibContextName`
pub const MIB_CONTEXT_NAME: ElementId = ElementId::iana(450);

/// `mibObjectName`
pub const MIB_OBJECT_NAME: ElementId = ElementId::iana(451);

/// `mibObjectDescription`
pub const MIB_OBJECT_DESCRIPTION: ElementId = ElementId::iana(452);

/// `mibObjectSyntax`
pub const MIB_OBJECT_SYNTAX: ElementId = ElementId::iana(453);

/// `mibModuleName`
pub const MIB_MODULE_NAME: ElementId = ElementId::iana(454);

/// `mobileIMSI`
pub const MOBILE_IMSI: ElementId = ElementId::iana(455);

/// `mobileMSISDN`
pub const MOBILE_MSISDN: ElementId = ElementId::iana(456);

/// `httpStatusCode`
pub const HTTP_STATUS_CODE: ElementId = ElementId::iana(457);

/// `sourceTransportPortsLimit`
pub const SOURCE_TRANSPORT_PORTS_LIMIT: ElementId = ElementId::iana(458);

/// `httpRequestMethod`
pub const HTTP_REQUEST_METHOD: ElementId = ElementId::iana(459);

/// `httpRequestHost`
pub const HTTP_REQUEST_HOST: ElementId = ElementId::iana(460);

/// `httpRequestTarget`
pub const HTTP_REQUEST_TARGET: ElementId = ElementId::iana(461);

/// `httpMessageVersion`
pub const HTTP_MESSAGE_VERSION: ElementId = ElementId::iana(462);

/// `natInstanceID`
pub const NAT_INSTANCE_ID: ElementId = ElementId::iana(463);

/// `internalAddressRealm`
pub const INTERNAL_ADDRESS_REALM: ElementId = ElementId::iana(464);

/// `externalAddressRealm`
pub const EXTERNAL_ADDRESS_REALM: ElementId = ElementId::iana(465);

/// `natQuotaExceededEvent`
pub const NAT_QUOTA_EXCEEDED_EVENT: ElementId = ElementId::iana(466);

/// `natThresholdEvent`
pub const NAT_THRESHOLD_EVENT: ElementId = ElementId::iana(467);

/// `httpUserAgent`
pub const HTTP_USER_AGENT: ElementId = ElementId::iana(468);

/// `httpContentType`
pub const HTTP_CONTENT_TYPE: ElementId = ElementId::iana(469);

/// `httpReasonPhrase`
pub const HTTP_REASON_PHRASE: ElementId = ElementId::iana(470);

/// `maxSessionEntries`
pub const MAX_SESSION_ENTRIES: ElementId = ElementId::iana(471);

/// `maxBIBEntries`
pub const MAX_BIB_ENTRIES: ElementId = ElementId::iana(472);

/// `maxEntriesPerUser`
pub const MAX_ENTRIES_PER_USER: ElementId = ElementId::iana(473);

/// `maxSubscribers`
pub const MAX_SUBSCRIBERS: ElementId = ElementId::iana(474);

/// `maxFragmentsPendingReassembly`
pub const MAX_FRAGMENTS_PENDING_REASSEMBLY: ElementId = ElementId::iana(475);

/// `addressPoolHighThreshold`
pub const ADDRESS_POOL_HIGH_THRESHOLD: ElementId = ElementId::iana(476);

/// `addressPoolLowThreshold`
pub const ADDRESS_POOL_LOW_THRESHOLD: ElementId = ElementId::iana(477);

/// `addressPortMappingHighThreshold`
pub const ADDRESS_PORT_MAPPING_HIGH_THRESHOLD: ElementId = ElementId::iana(478);

/// `addressPortMappingLowThreshold`
pub const ADDRESS_PORT_MAPPING_LOW_THRESHOLD: ElementId = ElementId::iana(479);

/// `addressPortMappingPerUserHighThreshold`
pub const ADDRESS_PORT_MAPPING_PER_USER_HIGH_THRESHOLD: ElementId = ElementId::iana(480);

/// `globalAddressMappingHighThreshold`
pub const GLOBAL_ADDRESS_MAPPING_HIGH_THRESHOLD: ElementId = ElementId::iana(481);

/// `vpnIdentifier`
pub const VPN_IDENTIFIER: ElementId = ElementId::iana(482);

/// `bgpCommunity`
pub const BGP_COMMUNITY: ElementId = ElementId::iana(483);

/// `bgpSourceCommunityList`
pub const BGP_SOURCE_COMMUNITY_LIST: ElementId = ElementId::iana(484);

/// `bgpDestinationCommunityList`
pub const BGP_DESTINATION_COMMUNITY_LIST: ElementId = ElementId::iana(485);

/// `bgpExtendedCommunity`
pub const BGP_EXTENDED_COMMUNITY: ElementId = ElementId::iana(486);

/// `bgpSourceExtendedCommunityList`
pub const BGP_SOURCE_EXTENDED_COMMUNITY_LIST: ElementId = ElementId::iana(487);

/// `bgpDestinationExtendedCommunityList`
pub const BGP_DESTINATION_EXTENDED_COMMUNITY_LIST: ElementId = ElementId::iana(488);

/// `bgpLargeCommunity`
pub const BGP_LARGE_COMMUNITY: ElementId = ElementId::iana(489);

/// `bgpSourceLargeCommunityList`
pub const BGP_SOURCE_LARGE_COMMUNITY_LIST: ElementId = ElementId::iana(490);

/// `bgpDestinationLargeCommunityList`
pub const BGP_DESTINATION_LARGE_COMMUNITY_LIST: ElementId = ElementId::iana(491);

/// `srhFlagsIPv6`
pub const SRH_FLAGS_IPV6: ElementId = ElementId::iana(492);

/// `srhTagIPv6`
pub const SRH_TAG_IPV6: ElementId = ElementId::iana(493);

/// `srhSegmentIPv6`
pub const SRH_SEGMENT_IPV6: ElementId = ElementId::iana(494);

/// `srhActiveSegmentIPv6`
pub const SRH_ACTIVE_SEGMENT_IPV6: ElementId = ElementId::iana(495);

/// `srhSegmentIPv6BasicList`
pub const SRH_SEGMENT_IPV6_BASIC_LIST: ElementId = ElementId::iana(496);

/// `srhSegmentIPv6ListSection`
pub const SRH_SEGMENT_IPV6_LIST_SECTION: ElementId = ElementId::iana(497);

/// `srhSegmentsIPv6Left`
pub const SRH_SEGMENTS_IPV6_LEFT: ElementId = ElementId::iana(498);

/// `srhIPv6Section`
pub const SRH_IPV6_SECTION: ElementId = ElementId::iana(499);

/// `srhIPv6ActiveSegmentType`
pub const SRH_IPV6_ACTIVE_SEGMENT_TYPE: ElementId = ElementId::iana(500);

/// `srhSegmentIPv6LocatorLength`
pub const SRH_SEGMENT_IPV6_LOCATOR_LENGTH: ElementId = ElementId::iana(501);

/// `srhSegmentIPv6EndpointBehavior`
pub const SRH_SEGMENT_IPV6_ENDPOINT_BEHAVIOR: ElementId = ElementId::iana(502);

/// `transportChecksum`
pub const TRANSPORT_CHECKSUM: ElementId = ElementId::iana(503);

/// `icmpHeaderPacketSection`
pub const ICMP_HEADER_PACKET_SECTION: ElementId = ElementId::iana(504);

/// `gtpuFlags`
pub const GTPU_FLAGS: ElementId = ElementId::iana(505);

/// `gtpuMsgType`
pub const GTPU_MSG_TYPE: ElementId = ElementId::iana(506);

/// `gtpuTEid`
pub const GTPU_T_EID: ElementId = ElementId::iana(507);

/// `gtpuSequenceNum`
pub const GTPU_SEQUENCE_NUM: ElementId = ElementId::iana(508);

/// `gtpuQFI`
pub const GTPU_QFI: ElementId = ElementId::iana(509);

/// `gtpuPduType`
pub const GTPU_PDU_TYPE: ElementId = ElementId::iana(510);

/// `bgpSourceAsPathList`
pub const BGP_SOURCE_AS_PATH_LIST: ElementId = ElementId::iana(511);

/// `bgpDestinationAsPathList`
pub const BGP_DESTINATION_AS_PATH_LIST: ElementId = ElementId::iana(512);

/// `ipv6ExtensionHeaderType`
pub const IPV6_EXTENSION_HEADER_TYPE: ElementId = ElementId::iana(513);

/// `ipv6ExtensionHeaderCount`
pub const IPV6_EXTENSION_HEADER_COUNT: ElementId = ElementId::iana(514);

/// `ipv6ExtensionHeadersFull`
pub const IPV6_EXTENSION_HEADERS_FULL: ElementId = ElementId::iana(515);

/// `ipv6ExtensionHeaderTypeCountList`
pub const IPV6_EXTENSION_HEADER_TYPE_COUNT_LIST: ElementId = ElementId::iana(516);

/// `ipv6ExtensionHeadersLimit`
pub const IPV6_EXTENSION_HEADERS_LIMIT: ElementId = ElementId::iana(517);

/// `ipv6ExtensionHeadersChainLength`
pub const IPV6_EXTENSION_HEADERS_CHAIN_LENGTH: ElementId = ElementId::iana(518);

/// `ipv6ExtensionHeaderChainLengthList`
pub const IPV6_EXTENSION_HEADER_CHAIN_LENGTH_LIST: ElementId = ElementId::iana(519);

/// `tcpOptionsFull`
pub const TCP_OPTIONS_FULL: ElementId = ElementId::iana(520);

/// `tcpSharedOptionExID16`
pub const TCP_SHARED_OPTION_EX_ID16: ElementId = ElementId::iana(521);

/// `tcpSharedOptionExID32`
pub const TCP_SHARED_OPTION_EX_ID32: ElementId = ElementId::iana(522);

/// `tcpSharedOptionExID16List`
pub const TCP_SHARED_OPTION_EX_ID16_LIST: ElementId = ElementId::iana(523);

/// `tcpSharedOptionExID32List`
pub const TCP_SHARED_OPTION_EX_ID32_LIST: ElementId = ElementId::iana(524);

/// `udpSafeOptions`
pub const UDP_SAFE_OPTIONS: ElementId = ElementId::iana(525);

/// `udpUnsafeOptions`
pub const UDP_UNSAFE_OPTIONS: ElementId = ElementId::iana(526);

/// `udpExID`
pub const UDP_EX_ID: ElementId = ElementId::iana(527);

/// `udpSafeExIDList`
pub const UDP_SAFE_EX_ID_LIST: ElementId = ElementId::iana(528);

/// `udpUnsafeExIDList`
pub const UDP_UNSAFE_EX_ID_LIST: ElementId = ElementId::iana(529);

/// `pathDelayMeanDeltaMicroseconds`
pub const PATH_DELAY_MEAN_DELTA_MICROSECONDS: ElementId = ElementId::iana(530);

/// `pathDelayMinDeltaMicroseconds`
pub const PATH_DELAY_MIN_DELTA_MICROSECONDS: ElementId = ElementId::iana(531);

/// `pathDelayMaxDeltaMicroseconds`
pub const PATH_DELAY_MAX_DELTA_MICROSECONDS: ElementId = ElementId::iana(532);

/// `pathDelaySumDeltaMicroseconds`
pub const PATH_DELAY_SUM_DELTA_MICROSECONDS: ElementId = ElementId::iana(533);
