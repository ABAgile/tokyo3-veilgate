package secret

// Needle kinds, combined into a mask so one trie serves both the response
// scrub, which may only replace configured values, and sanitization, which
// collapses values and placeholders alike.
const (
	kindValue uint8 = 1 << iota
	kindPlaceholder
)

// maskedPrefixLength is the number of leading value bytes that must appear
// before a masked rendering can possibly match. maskedSecretLength never
// accepts a visible prefix shorter than this, so requiring it is a necessary
// condition for a match and therefore safe as a prefilter.
const maskedPrefixLength = 4

type needleRef struct {
	secret int
	kind   uint8
}

type trieEdge struct {
	label byte
	next  *trieNode
}

// trieNode holds the needles ending at one point in the trie. Inner nodes
// almost always have a single edge, so a linear scan over a slice beats a map
// here and keeps the node small.
type trieNode struct {
	edges  []trieEdge
	refs   []needleRef
	masked []int // secrets whose value prefix ends at this node
	depth  int
}

func (n *trieNode) child(label byte) *trieNode {
	for i := range n.edges {
		if n.edges[i].label == label {
			return n.edges[i].next
		}
	}
	return nil
}

// needleTrie finds the longest configured needle starting at a given offset in
// a single walk.
//
// Matching every needle at every offset made scrubbing cost scale with the
// number of configured secrets, which let one large allowed response consume
// seconds of CPU. Walking a trie instead bounds the work at each offset by how
// far the data actually follows a configured needle, which is one byte for
// almost every offset in ordinary traffic, no matter how many secrets exist.
//
// The trie is built once when the broker is constructed and is read-only
// afterwards, so concurrent requests share it without synchronisation.
type needleTrie struct {
	root [256]*trieNode
}

func newNeedleTrie(secrets []resolved) *needleTrie {
	trie := new(needleTrie)
	for index := range secrets {
		item := &secrets[index]
		for _, representation := range item.representations {
			trie.add(representation, index, kindValue)
		}
		for _, representation := range item.placeholderRepresentations {
			trie.add(representation, index, kindPlaceholder)
		}
		if len(item.valueBytes) >= maskedPrefixLength*2 {
			trie.addMaskedPrefix(item.valueBytes[:maskedPrefixLength], index)
		}
	}
	return trie
}

func (t *needleTrie) walkTo(needle []byte) *trieNode {
	node := t.root[needle[0]]
	if node == nil {
		node = &trieNode{depth: 1}
		t.root[needle[0]] = node
	}
	for _, label := range needle[1:] {
		next := node.child(label)
		if next == nil {
			next = &trieNode{depth: node.depth + 1}
			node.edges = append(node.edges, trieEdge{label: label, next: next})
		}
		node = next
	}
	return node
}

func (t *needleTrie) add(needle []byte, secret int, kind uint8) {
	if len(needle) == 0 {
		return
	}
	node := t.walkTo(needle)
	node.refs = append(node.refs, needleRef{secret: secret, kind: kind})
}

// addMaskedPrefix records secret as a candidate for masked-rendering detection
// at this prefix. Candidates stay in secret order so the caller resolves ties
// the same way a scan over the configured secrets would.
func (t *needleTrie) addMaskedPrefix(prefix []byte, secret int) {
	node := t.walkTo(prefix)
	node.masked = append(node.masked, secret)
}

// longest reports the longest needle starting at data[0], restricted to the
// given kinds and, when scope is non-nil, to secrets scope marks as in scope.
// It also reports the masked-rendering candidates passed on the way, which the
// caller consults only when no exact needle matched.
func (t *needleTrie) longest(data []byte, kinds uint8, scope []bool) (length, secret int, masked []int) {
	node := t.root[data[0]]
	if node == nil {
		return 0, 0, nil
	}
	for i := 1; ; i++ {
		if len(node.masked) > 0 {
			masked = node.masked
		}
		for _, candidate := range node.refs {
			if candidate.kind&kinds == 0 || (scope != nil && !scope[candidate.secret]) {
				continue
			}
			// Deeper nodes overwrite this, so the last write is the longest
			// acceptable needle at this offset.
			length, secret = node.depth, candidate.secret
			break
		}
		if i >= len(data) {
			return length, secret, masked
		}
		next := node.child(data[i])
		if next == nil {
			return length, secret, masked
		}
		node = next
	}
}
