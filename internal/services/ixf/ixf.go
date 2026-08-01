package ixf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type Export struct {
	MemberList []Member `json:"member_list"`
}

type Member struct {
	Asn        int    `json:"asnum"`
	Name       string `json:"name"`
	Connection []Conn `json:"connection_list"`
}

type Conn struct {
	VlanList []Vlan `json:"vlan_list"`
}

type Vlan struct {
	IPv4 *Addr `json:"ipv4"`
	IPv6 *Addr `json:"ipv6"`
}

type Addr struct {
	Address string   `json:"address"`
	MAC     []string `json:"mac_addresses"`
}

type AddressInfo struct {
	MAC  string
	IPv4 string
	IPv6 string
}

type PeerInfo struct {
	Name      string
	ASN       int
	Addresses []AddressInfo
}

type PeerMap struct {
	Peers map[int]*PeerInfo `json:"peers"`
	MACs  map[string]*PeerInfo

	mu sync.RWMutex
}

func NewPeerMap() *PeerMap {
	return new(PeerMap{
		Peers: make(map[int]*PeerInfo),
		MACs:  make(map[string]*PeerInfo),
	})
}

func (pm *PeerMap) AddPeerInfo(name string, asn int) {
	if _, ok := pm.Peers[asn]; !ok {
		pm.Peers[asn] = new(PeerInfo{
			Name:      name,
			ASN:       asn,
			Addresses: make([]AddressInfo, 0, 2),
		})
	}
}

func (pm *PeerMap) AddPeerAddress(asn int, mac, v4addr, v6addr string) error {
	if _, ok := pm.Peers[asn]; !ok {
		return fmt.Errorf("peer AS%d not found", asn)
	}

	pm.Peers[asn].Addresses = append(pm.Peers[asn].Addresses, AddressInfo{
		MAC:  mac,
		IPv4: v4addr,
		IPv6: v6addr,
	})

	pm.MACs[mac] = pm.Peers[asn]
	return nil
}

func (pm *PeerMap) PopulateFromURL(url string) error {

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %s", resp.Status)
	}

	var export Export
	if err = json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// cleanup
	pm.Peers = make(map[int]*PeerInfo)
	pm.MACs = make(map[string]*PeerInfo)

	for _, member := range export.MemberList {
		pm.AddPeerInfo(member.Name, member.Asn)
		for _, conn := range member.Connection {
			for _, vlan := range conn.VlanList {
				ipv4 := ""
				ipv6 := ""

				if vlan.IPv6 != nil {
					ipv6 = vlan.IPv6.Address
				}

				if vlan.IPv4 != nil {
					ipv4 = vlan.IPv4.Address
					for _, mac := range vlan.IPv4.MAC {
						_ = pm.AddPeerAddress(member.Asn, mac, ipv4, ipv6)
					}
				}
			}
		}
	}

	return nil
}
