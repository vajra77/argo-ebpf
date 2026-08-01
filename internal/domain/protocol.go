package domain

type ProtocolType uint16

const (
	ProtoUnknown ProtocolType = 0
	ProtoARPReq  ProtocolType = 1
	ProtoIPv6RA  ProtocolType = 2
	ProtoMDNS    ProtocolType = 3
	ProtoLLMNR   ProtocolType = 4
	ProtoCDPLLDP ProtocolType = 5
)

func (p ProtocolType) String() string {
	switch p {
	case ProtoARPReq:
		return "ARP_REQUEST"
	case ProtoIPv6RA:
		return "IPV6_ROUTER_ADVERTISEMENT"
	case ProtoMDNS:
		return "MDNS"
	case ProtoLLMNR:
		return "LLMNR"
	case ProtoCDPLLDP:
		return "CDP_LLDP"
	default:
		return "UNKNOWN"
	}
}

func ProtocolToViolationType(p ProtocolType) ViolationType {
	switch p {
	case ProtoIPv6RA:
		return ViolationIPv6RA
	case ProtoMDNS:
		return ViolationMDNS
	case ProtoLLMNR:
		return ViolationLLMNR
	case ProtoCDPLLDP:
		return ViolationCDP
	default:
		return "UNKNOWN_VIOLATION"
	}
}
