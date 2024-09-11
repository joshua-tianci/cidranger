package cidranger

import (
	"fmt"
	"net"
	"strings"

	rnet "github.com/joshua-tianci/cidranger/net"
)

// PrefixTrie is a path-compressed (PC) trie implementation of the
// ranger interface inspired by this blog post:
// https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux
//
// CIDR blocks are stored using a prefix tree structure where each node has its
// parent as prefix, and the path from the root node represents current CIDR
// block.
//
// For IPv4, the trie structure guarantees max depth of 32 as IPv4 addresses are
// 32 bits long and each bit represents a prefix tree starting at that bit. This
// property also guarantees constant lookup time in Big-O notation.
//
// Path compression compresses a string of node with only 1 child into a single
// node, decrease the amount of lookups necessary during containment tests.
//
// Level compression dictates the amount of direct children of a node by
// allowing it to handle multiple bits in the path.  The heuristic (based on
// children population) to decide when the compression and decompression happens
// is outlined in the prior linked blog, and will be experimented with in more
// depth in this project in the future.
//
// Note: Can not insert both IPv4 and IPv6 network addresses into the same
// prefix trie, use versionedRanger wrapper instead.
//
// TODO: Implement level-compressed component of the LPC trie.
type PrefixTrie struct {
	Children    [2]*PrefixTrie `json:"children"`
	Parent      *PrefixTrie    `json:"parent"`
	Entry       RangerEntry    `json:"entry"`
	Network     rnet.Network   `json:"network"`
	Size        int            `json:"size,omitempty"` // This is only maintained in the root trie.
	BitsSkipped uint           `json:"bits_skipped"`
	BitsHandled uint           `json:"bits_handled"`
}

var ip4ZeroCIDR, ip6ZeroCIDR net.IPNet

func init() {
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("0::0/0")
	ip4ZeroCIDR = *v4
	ip6ZeroCIDR = *v6
}

func newRanger(version rnet.IPVersion) Ranger {
	return newPrefixTree(version)
}

// newPrefixTree creates a new prefixTrie.
func newPrefixTree(version rnet.IPVersion) *PrefixTrie {
	rootNet := ip4ZeroCIDR
	if version == rnet.IPv6 {
		rootNet = ip6ZeroCIDR
	}
	return &PrefixTrie{
		BitsSkipped: 0,
		BitsHandled: 1,
		Network:     rnet.NewNetwork(rootNet),
	}
}

func newPathprefixTrie(network rnet.Network, numBitsSkipped uint) *PrefixTrie {
	version := rnet.IPv4
	if len(network.Number) == rnet.IPv6Uint32Count {
		version = rnet.IPv6
	}
	path := newPrefixTree(version)
	path.BitsSkipped = numBitsSkipped
	path.Network = network.Masked(int(numBitsSkipped))
	return path
}

func newEntryTrie(network rnet.Network, entry RangerEntry) *PrefixTrie {
	leaf := newPathprefixTrie(network, uint(network.Mask))
	leaf.Entry = entry
	return leaf
}

// Insert inserts a RangerEntry into prefix trie.
func (p *PrefixTrie) Insert(entry RangerEntry) error {
	network := entry.Network()
	sizeIncreased, err := p.insert(rnet.NewNetwork(network), entry)
	if sizeIncreased {
		p.Size++
	}
	return err
}

// Remove removes RangerEntry identified by given network from trie.
func (p *PrefixTrie) Remove(network net.IPNet) (RangerEntry, error) {
	entry, err := p.remove(rnet.NewNetwork(network))
	if entry != nil {
		p.Size--
	}
	return entry, err
}

// Contains returns boolean indicating whether given ip is contained in any
// of the inserted networks.
func (p *PrefixTrie) Contains(ip net.IP) (bool, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return false, ErrInvalidNetworkNumberInput
	}
	return p.contains(nn)
}

// ContainingNetworks returns the list of RangerEntry(s) the given ip is
// contained in in ascending prefix order.
func (p *PrefixTrie) ContainingNetworks(ip net.IP) ([]RangerEntry, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return nil, ErrInvalidNetworkNumberInput
	}
	return p.containingNetworks(nn)
}

// CoveredNetworks returns the list of RangerEntry(s) the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (p *PrefixTrie) CoveredNetworks(network net.IPNet) ([]RangerEntry, error) {
	return p.coveredNetworks(rnet.NewNetwork(network))
}

// Len returns number of networks in ranger.
func (p *PrefixTrie) Len() int {
	return p.Size
}

// String returns string representation of trie, mainly for visualization and
// debugging.
func (p *PrefixTrie) String() string {
	children := []string{}
	padding := strings.Repeat("| ", p.level()+1)
	for bits, child := range p.Children {
		if child == nil {
			continue
		}
		childStr := fmt.Sprintf("\n%s%d--> %s", padding, bits, child.String())
		children = append(children, childStr)
	}
	return fmt.Sprintf("%s (target_pos:%d:has_entry:%t)%s", p.Network,
		p.targetBitPosition(), p.hasEntry(), strings.Join(children, ""))
}

func (p *PrefixTrie) contains(number rnet.NetworkNumber) (bool, error) {
	if !p.Network.Contains(number) {
		return false, nil
	}
	if p.hasEntry() {
		return true, nil
	}
	if p.targetBitPosition() < 0 {
		return false, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return false, err
	}
	child := p.Children[bit]
	if child != nil {
		return child.contains(number)
	}
	return false, nil
}

func (p *PrefixTrie) containingNetworks(number rnet.NetworkNumber) ([]RangerEntry, error) {
	results := []RangerEntry{}
	if !p.Network.Contains(number) {
		return results, nil
	}
	if p.hasEntry() {
		results = []RangerEntry{p.Entry}
	}
	if p.targetBitPosition() < 0 {
		return results, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return nil, err
	}
	child := p.Children[bit]
	if child != nil {
		ranges, err := child.containingNetworks(number)
		if err != nil {
			return nil, err
		}
		if len(ranges) > 0 {
			if len(results) > 0 {
				results = append(results, ranges...)
			} else {
				results = ranges
			}
		}
	}
	return results, nil
}

func (p *PrefixTrie) coveredNetworks(network rnet.Network) ([]RangerEntry, error) {
	var results []RangerEntry
	if network.Covers(p.Network) {
		for entry := range p.walkDepth() {
			results = append(results, entry)
		}
	} else if p.targetBitPosition() >= 0 {
		bit, err := p.targetBitFromIP(network.Number)
		if err != nil {
			return results, err
		}
		child := p.Children[bit]
		if child != nil {
			return child.coveredNetworks(network)
		}
	}
	return results, nil
}

func (p *PrefixTrie) insert(network rnet.Network, entry RangerEntry) (bool, error) {
	if p.Network.Equal(network) {
		sizeIncreased := p.Entry == nil
		p.Entry = entry
		return sizeIncreased, nil
	}

	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return false, err
	}
	existingChild := p.Children[bit]

	// No existing child, insert new leaf trie.
	if existingChild == nil {
		p.appendTrie(bit, newEntryTrie(network, entry))
		return true, nil
	}

	// Check whether it is necessary to insert additional path prefix between current trie and existing child,
	// in the case that inserted network diverges on its path to existing child.
	lcb, err := network.LeastCommonBitPosition(existingChild.Network)
	if err != nil {
		return false, err
	}

	divergingBitPos := int(lcb) - 1
	if divergingBitPos > existingChild.targetBitPosition() {
		pathPrefix := newPathprefixTrie(network, p.totalNumberOfBits()-lcb)
		err := p.insertPrefix(bit, pathPrefix, existingChild)
		if err != nil {
			return false, err
		}
		// Update new child
		existingChild = pathPrefix
	}
	return existingChild.insert(network, entry)
}

func (p *PrefixTrie) appendTrie(bit uint32, prefix *PrefixTrie) {
	p.Children[bit] = prefix
	prefix.Parent = p
}

func (p *PrefixTrie) insertPrefix(bit uint32, pathPrefix, child *PrefixTrie) error {
	// Set parent/child relationship between current trie and inserted pathPrefix
	p.Children[bit] = pathPrefix
	pathPrefix.Parent = p

	// Set parent/child relationship between inserted pathPrefix and original child
	pathPrefixBit, err := pathPrefix.targetBitFromIP(child.Network.Number)
	if err != nil {
		return err
	}
	pathPrefix.Children[pathPrefixBit] = child
	child.Parent = pathPrefix
	return nil
}

func (p *PrefixTrie) remove(network rnet.Network) (RangerEntry, error) {
	if p.hasEntry() && p.Network.Equal(network) {
		entry := p.Entry
		p.Entry = nil

		err := p.compressPathIfPossible()
		if err != nil {
			return nil, err
		}
		return entry, nil
	}
	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return nil, err
	}
	child := p.Children[bit]
	if child != nil {
		return child.remove(network)
	}
	return nil, nil
}

func (p *PrefixTrie) qualifiesForPathCompression() bool {
	// Current prefix trie can be path compressed if it meets all following.
	//		1. records no CIDR entry
	//		2. has single or no child
	//		3. is not root trie
	return !p.hasEntry() && p.childrenCount() <= 1 && p.Parent != nil
}

func (p *PrefixTrie) compressPathIfPossible() error {
	if !p.qualifiesForPathCompression() {
		// Does not qualify to be compressed
		return nil
	}

	// Find lone child.
	var loneChild *PrefixTrie
	for _, child := range p.Children {
		if child != nil {
			loneChild = child
			break
		}
	}

	// Find root of current single child lineage.
	current := p.Parent
	for {
		if !current.qualifiesForPathCompression() {
			break
		}
		current = current.Parent
	}
	parentBit, err := current.targetBitFromIP(p.Network.Number)
	if err != nil {
		return err
	}
	current.Children[parentBit] = loneChild

	// Attempts to further apply path compression at current lineage parent, in case current lineage
	// compressed into parent.
	return current.compressPathIfPossible()
}

func (p *PrefixTrie) childrenCount() int {
	count := 0
	for _, child := range p.Children {
		if child != nil {
			count++
		}
	}
	return count
}

func (p *PrefixTrie) totalNumberOfBits() uint {
	return rnet.BitsPerUint32 * uint(len(p.Network.Number))
}

func (p *PrefixTrie) targetBitPosition() int {
	return int(p.totalNumberOfBits()-p.BitsSkipped) - 1
}

func (p *PrefixTrie) targetBitFromIP(n rnet.NetworkNumber) (uint32, error) {
	// This is a safe uint boxing of int since we should never attempt to get
	// target bit at a negative position.
	return n.Bit(uint(p.targetBitPosition()))
}

func (p *PrefixTrie) hasEntry() bool {
	return p.Entry != nil
}

func (p *PrefixTrie) level() int {
	if p.Parent == nil {
		return 0
	}
	return p.Parent.level() + 1
}

// walkDepth walks the trie in depth order, for unit testing.
func (p *PrefixTrie) walkDepth() <-chan RangerEntry {
	entries := make(chan RangerEntry)
	go func() {
		if p.hasEntry() {
			entries <- p.Entry
		}
		childEntriesList := []<-chan RangerEntry{}
		for _, trie := range p.Children {
			if trie == nil {
				continue
			}
			childEntriesList = append(childEntriesList, trie.walkDepth())
		}
		for _, childEntries := range childEntriesList {
			for entry := range childEntries {
				entries <- entry
			}
		}
		close(entries)
	}()
	return entries
}
