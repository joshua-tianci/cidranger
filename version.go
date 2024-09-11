package cidranger

import (
	"net"

	rnet "github.com/joshua-tianci/cidranger/net"
)

type rangerFactory func(rnet.IPVersion) Ranger

type VersionedRanger struct {
	V4Ranger Ranger `json:"ipv4"`
	V6Ranger Ranger `json:"ipv6"`
}

func newVersionedRanger(factory rangerFactory) Ranger {
	return &VersionedRanger{
		V4Ranger: factory(rnet.IPv4),
		V6Ranger: factory(rnet.IPv6),
	}
}

func (v *VersionedRanger) Insert(entry RangerEntry) error {
	network := entry.Network()
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return err
	}
	return ranger.Insert(entry)
}

func (v *VersionedRanger) Remove(network net.IPNet) (RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return nil, err
	}
	return ranger.Remove(network)
}

func (v *VersionedRanger) Contains(ip net.IP) (bool, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return false, err
	}
	return ranger.Contains(ip)
}

func (v *VersionedRanger) ContainingNetworks(ip net.IP) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return nil, err
	}
	return ranger.ContainingNetworks(ip)
}

func (v *VersionedRanger) CoveredNetworks(network net.IPNet) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return nil, err
	}
	return ranger.CoveredNetworks(network)
}

// Len returns number of networks in ranger.
func (v *VersionedRanger) Len() int {
	return v.V4Ranger.Len() + v.V6Ranger.Len()
}

func (v *VersionedRanger) getRangerForIP(ip net.IP) (Ranger, error) {
	if ip.To4() != nil {
		return v.V4Ranger, nil
	}
	if ip.To16() != nil {
		return v.V6Ranger, nil
	}
	return nil, ErrInvalidNetworkNumberInput
}
