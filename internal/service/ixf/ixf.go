package ixf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func PopulateFromURL(url string) (*models.MapData, error) {

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	var export Export
	if err := json.NewDecoder(resp.Body).Decode(&export); err != nil {
		return nil, err
	}

	mapData := models.NewMapData()

	for _, member := range export.MemberList {
		asnStr := fmt.Sprintf("%d", member.Asn)
		mapData.AddName(asnStr, member.Name)
		for _, conn := range member.Connection {
			for _, vlan := range conn.VlanList {
				ipv4 := ""
				ipv6 := ""

				if vlan.IPv4 != nil {
					ipv4 = vlan.IPv4.Address
					for _, mac := range vlan.IPv4.MAC {
						mapData.AddAddressMap(asnStr, ipv4, ipv6, mac)
					}
				}

				if vlan.IPv6 != nil {
					ipv6 = vlan.IPv6.Address
					for _, mac := range vlan.IPv6.MAC {
						mapData.AddAddressMap(asnStr, ipv4, ipv6, mac)
					}
				}
			}
		}
	}

	return mapData, nil
}
