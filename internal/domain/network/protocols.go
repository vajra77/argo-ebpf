/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package network

import "argo-ebpf/internal/domain/peer"

type ProtocolType uint16

const (
	ProtoUnknown ProtocolType = 0
	ProtoARPReq  ProtocolType = 1
	ProtoIPv6RA  ProtocolType = 2
	ProtoMDNS    ProtocolType = 3
	ProtoLLMNR   ProtocolType = 4
	ProtoCDPLLDP ProtocolType = 5
)

// String converts a ProtocolType to a string
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

func ProtocolToAlertType(p ProtocolType) peer.AlertType {
	switch p {
	case ProtoIPv6RA:
		return peer.AlertIPv6RA
	case ProtoMDNS:
		return peer.AlertMDNS
	case ProtoLLMNR:
		return peer.AlertLLMNR
	case ProtoCDPLLDP:
		return peer.AlertCDP
	default:
		return "UNKNOWN_VIOLATION"
	}
}
