// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"slices"
)

// Group membership: a deliberately small subset of MLS, the same as
// MoqomMLS's Group.swift, which documents what it guarantees.
//
// No ratchet tree: members are a flat list of leaves, and a commit seals its
// commit secret to every remaining member's leaf key directly, which is what
// TreeKEM degenerates to when every parent node is blank. The GroupContext's
// tree_hash is a hash of that list. Proposals are Add and Remove, carried by
// value in the commit that applies them; an empty commit is an Update, which
// refreshes the committer's leaf key.

// Leaf is one member, as the group knows them.
type Leaf struct {
	// Identity is the MOQOM identity, username/device, as UTF-8.
	Identity      []byte
	SignatureKey  []byte
	EncryptionKey []byte
}

func (l *Leaf) write(w *writer) {
	w.vector(l.Identity)
	w.vector(l.SignatureKey)
	w.vector(l.EncryptionKey)
}

func (l *Leaf) equal(other *Leaf) bool {
	return other != nil && bytes.Equal(l.Identity, other.Identity) &&
		bytes.Equal(l.SignatureKey, other.SignatureKey) && bytes.Equal(l.EncryptionKey, other.EncryptionKey)
}

// members is the list of leaves, nil where a member was removed.
type members []*Leaf

func (m members) encode() []byte {
	var w writer
	w.uint32(uint32(len(m)))
	for _, leaf := range m {
		if leaf == nil {
			w.uint8(0)
			continue
		}
		w.uint8(1)
		leaf.write(&w)
	}
	return w.bytes
}

func readMembers(r *reader) members {
	count := r.uint32()
	if count > 1<<16 {
		r.fail("member count")
		return nil
	}
	var m members
	for i := uint32(0); i < count && r.err == nil; i++ {
		switch r.uint8() {
		case 0:
			m = append(m, nil)
		case 1:
			m = append(m, &Leaf{Identity: r.vector(), SignatureKey: r.vector(), EncryptionKey: r.vector()})
		default:
			r.fail("leaf presence")
		}
	}
	return m
}

// hash fills the GroupContext's tree_hash slot. Not the RFC's tree hash, since
// there is no tree.
func (m members) hash(suite CipherSuite) []byte {
	return suite.RefHash("MOQOM 1.0 Member List", m.encode())
}

func (m members) leaf(index uint32) *Leaf {
	if int(index) < len(m) {
		return m[index]
	}
	return nil
}

type proposal struct {
	add    *KeyPackage
	remove uint32
}

func (p proposal) write(w *writer) {
	if p.add != nil {
		w.uint16(1)
		w.vector(p.add.Encode())
		return
	}
	w.uint16(3)
	w.uint32(p.remove)
}

type addedLeaf struct {
	leaf       uint32
	keyPackage *KeyPackage
}

// apply removes, then adds into the leftmost blank, then trims trailing
// blanks: in that order on every member, which is what keeps leaf indices
// agreed without sending them.
func (m members) apply(proposals []proposal, suite CipherSuite) (members, []addedLeaf, error) {
	next := slices.Clone(m)
	for _, p := range proposals {
		if p.add == nil {
			if next.leaf(p.remove) == nil {
				return nil, nil, fmt.Errorf("%w: remove of leaf %d", ErrInvalidProposal, p.remove)
			}
			next[p.remove] = nil
		}
	}
	var added []addedLeaf
	for _, p := range proposals {
		if p.add == nil {
			continue
		}
		if p.add.CipherSuite != suite {
			return nil, nil, fmt.Errorf("%w: group %#04x, package %#04x", ErrCipherSuiteMismatch, uint16(suite), uint16(p.add.CipherSuite))
		}
		if err := p.add.Verify(); err != nil {
			return nil, nil, err
		}
		for _, leaf := range next {
			if leaf != nil && (bytes.Equal(leaf.SignatureKey, p.add.SignatureKey) ||
				bytes.Equal(leaf.EncryptionKey, p.add.EncryptionKey) || bytes.Equal(leaf.Identity, p.add.Identity)) {
				return nil, nil, fmt.Errorf("%w: %q is already a member", ErrInvalidProposal, p.add.Identity)
			}
		}
		slot := slices.Index(next, nil)
		if slot < 0 {
			slot = len(next)
			next = append(next, nil)
		}
		next[slot] = p.add.leaf()
		added = append(added, addedLeaf{uint32(slot), p.add})
	}
	for len(next) > 0 && next[len(next)-1] == nil {
		next = next[:len(next)-1]
	}
	return next, added, nil
}

// CommitMessage is a commit, signed and confirmed, as it travels.
type CommitMessage struct {
	GroupID         []byte
	Epoch           uint64
	Sender          uint32
	commit          []byte
	signature       []byte
	confirmationTag []byte
}

// content is the FramedContent: what is signed (after the GroupContext) and
// what the confirmed transcript hash covers (before the signature).
func (c *CommitMessage) content() []byte {
	var w writer
	w.vector(c.GroupID)
	w.uint64(c.Epoch)
	w.uint32(c.Sender)
	w.vector(c.commit)
	return w.bytes
}

// Encode is the message as it travels.
func (c *CommitMessage) Encode() []byte {
	w := writer{bytes: c.content()}
	w.vector(c.signature)
	w.vector(c.confirmationTag)
	return w.bytes
}

// DecodeCommitMessage reads a commit's framing. The signature, the sealed
// secrets and the confirmation tag are checked by Group.Process.
func DecodeCommitMessage(data []byte) (*CommitMessage, error) {
	r := &reader{data: data}
	c := &CommitMessage{GroupID: r.vector(), Epoch: r.uint64(), Sender: r.uint32(), commit: r.vector(), signature: r.vector(), confirmationTag: r.vector()}
	if err := r.finish(); err != nil {
		return nil, err
	}
	return c, nil
}

type sealedSecret struct {
	leaf       uint32
	ciphertext HPKECiphertext
}

// commitBody is a commit's proposals, the committer's new leaf key (the whole
// of the "path" here), and the commit secret sealed to each remaining member.
type commitBody struct {
	proposals     []proposal
	encryptionKey []byte
	secrets       []sealedSecret
}

func (b *commitBody) encode() []byte {
	var w writer
	w.uint32(uint32(len(b.proposals)))
	for _, p := range b.proposals {
		p.write(&w)
	}
	w.vector(b.encryptionKey)
	w.uint32(uint32(len(b.secrets)))
	for _, s := range b.secrets {
		w.uint32(s.leaf)
		s.ciphertext.write(&w)
	}
	return w.bytes
}

func decodeCommitBody(data []byte) (*commitBody, error) {
	r := &reader{data: data}
	count := r.uint32()
	if count > 1<<12 {
		r.fail("proposal count")
	}
	b := &commitBody{}
	for i := uint32(0); i < count && r.err == nil; i++ {
		switch kind := r.uint16(); kind {
		case 1:
			encoded := r.vector()
			if r.err != nil {
				break
			}
			k, err := DecodeKeyPackage(encoded)
			if err != nil {
				return nil, err
			}
			b.proposals = append(b.proposals, proposal{add: k})
		case 3:
			b.proposals = append(b.proposals, proposal{remove: r.uint32()})
		default:
			if r.err == nil {
				return nil, fmt.Errorf("%w: proposal type %d", ErrUnsupported, kind)
			}
		}
	}
	b.encryptionKey = r.vector()
	count = r.uint32()
	if count > 1<<16 {
		r.fail("secret count")
	}
	for i := uint32(0); i < count && r.err == nil; i++ {
		b.secrets = append(b.secrets, sealedSecret{leaf: r.uint32(), ciphertext: readHPKECiphertext(r)})
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	return b, nil
}

type welcomeSecretEntry struct {
	reference  []byte
	ciphertext HPKECiphertext
}

// Welcome is how a joiner enters: the joiner secret for each new member, and
// the group as it now is, encrypted under the welcome secret.
type Welcome struct {
	secrets            []welcomeSecretEntry
	encryptedGroupInfo []byte
}

// Encode is the Welcome as it travels.
func (w *Welcome) Encode() []byte {
	var out writer
	out.uint32(uint32(len(w.secrets)))
	for _, s := range w.secrets {
		out.vector(s.reference)
		s.ciphertext.write(&out)
	}
	out.vector(w.encryptedGroupInfo)
	return out.bytes
}

// DecodeWelcome reads a Welcome.
func DecodeWelcome(data []byte) (*Welcome, error) {
	r := &reader{data: data}
	count := r.uint32()
	if count > 1<<16 {
		r.fail("secret count")
	}
	w := &Welcome{}
	for i := uint32(0); i < count && r.err == nil; i++ {
		w.secrets = append(w.secrets, welcomeSecretEntry{reference: r.vector(), ciphertext: readHPKECiphertext(r)})
	}
	w.encryptedGroupInfo = r.vector()
	if err := r.finish(); err != nil {
		return nil, err
	}
	return w, nil
}

// IsAddressedTo reports whether the Welcome carries a secret for k.
func (w *Welcome) IsAddressedTo(k *KeyPackage) bool {
	reference := k.Reference()
	return slices.ContainsFunc(w.secrets, func(s welcomeSecretEntry) bool { return bytes.Equal(s.reference, reference) })
}

// Group is one member's view of a group at one epoch. Every transition
// returns a new Group; dropping the old one is what forward secrecy rests on.
type Group struct {
	ownLeaf           uint32
	members           members
	context           GroupContext
	secrets           *EpochSecrets
	interim           []byte
	encryptionPrivate []byte
	signaturePrivate  []byte
}

// GroupID is the group's identifier.
func (g *Group) GroupID() []byte { return g.context.GroupID }

// Epoch is the group's current epoch.
func (g *Group) Epoch() uint64 { return g.context.Epoch }

// CipherSuite is the suite the group was founded in.
func (g *Group) CipherSuite() CipherSuite { return g.context.CipherSuite }

// OwnLeaf is this member's leaf index.
func (g *Group) OwnLeaf() uint32 { return g.ownLeaf }

// Members is the leaves by index, nil where a member was removed.
func (g *Group) Members() []*Leaf { return slices.Clone(g.members) }

// EpochAuthenticator is RFC 9420's epoch_authenticator: equal on every
// member's device for the same epoch, and something two people can compare
// to know nobody is in the group that the other cannot see.
func (g *Group) EpochAuthenticator() []byte { return g.secrets.EpochAuthenticator }

// Exporter is MLS-Exporter, RFC 9420 §8.5, for this epoch.
func (g *Group) Exporter(label string, context []byte, length int) []byte {
	return g.secrets.Exporter(label, context, length)
}

// LeafOf is the leaf an identity occupies, if any.
func (g *Group) LeafOf(identity string) (uint32, bool) {
	for i, leaf := range g.members {
		if leaf != nil && string(leaf.Identity) == identity {
			return uint32(i), true
		}
	}
	return 0, false
}

func interim(suite CipherSuite, confirmed, tag []byte) []byte {
	w := writer{bytes: slices.Clone(confirmed)}
	w.vector(tag)
	return suite.hash(w.bytes)
}

func (g *Group) confirmed(content, signature []byte) []byte {
	w := writer{bytes: slices.Clone(g.interim)}
	w.raw(content)
	w.vector(signature)
	return g.CipherSuite().hash(w.bytes)
}

// CreateGroup starts a group with one member, in the suite of that member's
// key package.
func CreateGroup(groupID []byte, bundle *KeyPackageBundle) (*Group, error) {
	if err := bundle.KeyPackage.Verify(); err != nil {
		return nil, err
	}
	suite := bundle.KeyPackage.CipherSuite
	m := members{bundle.KeyPackage.leaf()}
	context := GroupContext{CipherSuite: suite, GroupID: groupID, Epoch: 0, TreeHash: m.hash(suite), ConfirmedTranscriptHash: []byte{}}
	secrets := DeriveEpochSecrets(suite.randomSecret(), suite.randomSecret(), nil, context)
	tag := suite.mac(secrets.ConfirmationKey, nil)
	return &Group{
		members:           m,
		context:           context,
		secrets:           secrets,
		interim:           interim(suite, nil, tag),
		encryptionPrivate: bundle.encryptionPrivate,
		signaturePrivate:  bundle.signaturePrivate,
	}, nil
}

// PendingCommit is a commit that has been built and not yet accepted. The
// group does not move until the delivery service orders it first for its
// epoch; Next is the state to adopt when it does.
type PendingCommit struct {
	Message *CommitMessage
	// Welcome is nil when the commit adds nobody.
	Welcome *Welcome
	// Joiners are the key packages added, which are who the Welcome is for.
	Joiners []*KeyPackage
	Next    *Group
}

// Commit builds a commit that adds and removes members and refreshes this
// member's leaf key. With nothing to add or remove it is a pure key rotation.
func (g *Group) Commit(adding []*KeyPackage, removing []uint32) (*PendingCommit, error) {
	suite := g.CipherSuite()
	if slices.Contains(removing, g.ownLeaf) {
		return nil, fmt.Errorf("%w: a committer cannot remove itself", ErrInvalidProposal)
	}
	sorted := slices.Sorted(slices.Values(removing))
	var proposals []proposal
	for _, leaf := range sorted {
		proposals = append(proposals, proposal{remove: leaf})
	}
	for _, k := range adding {
		proposals = append(proposals, proposal{add: k})
	}
	next, added, err := g.members.apply(proposals, suite)
	if err != nil {
		return nil, err
	}
	joiners := map[uint32]bool{}
	for _, a := range added {
		joiners[a.leaf] = true
	}

	encryptionPrivate, encryptionKey, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	own := next.leaf(g.ownLeaf)
	if own == nil {
		return nil, ErrRemoved
	}
	next[g.ownLeaf] = &Leaf{Identity: own.Identity, SignatureKey: own.SignatureKey, EncryptionKey: encryptionKey}

	commitSecret := suite.randomSecret()
	provisional := GroupContext{CipherSuite: suite, GroupID: g.GroupID(), Epoch: g.Epoch() + 1, TreeHash: next.hash(suite), ConfirmedTranscriptHash: g.context.ConfirmedTranscriptHash}
	encodedProvisional := provisional.Encode()
	body := &commitBody{proposals: proposals, encryptionKey: encryptionKey}
	for i, leaf := range next {
		index := uint32(i)
		if leaf == nil || index == g.ownLeaf || joiners[index] {
			continue
		}
		sealed, err := suite.EncryptWithLabel(leaf.EncryptionKey, "UpdatePathNode", encodedProvisional, commitSecret)
		if err != nil {
			return nil, err
		}
		body.secrets = append(body.secrets, sealedSecret{index, sealed})
	}

	message := &CommitMessage{GroupID: g.GroupID(), Epoch: g.Epoch(), Sender: g.ownLeaf, commit: body.encode()}
	message.signature, err = suite.SignWithLabel(g.signaturePrivate, "FramedContentTBS", append(g.context.Encode(), message.content()...))
	if err != nil {
		return nil, err
	}
	confirmed := g.confirmed(message.content(), message.signature)
	context := GroupContext{CipherSuite: suite, GroupID: g.GroupID(), Epoch: g.Epoch() + 1, TreeHash: next.hash(suite), ConfirmedTranscriptHash: confirmed}
	secrets := DeriveEpochSecrets(g.secrets.InitSecret, commitSecret, nil, context)
	message.confirmationTag = suite.mac(secrets.ConfirmationKey, confirmed)

	advanced := &Group{
		ownLeaf:           g.ownLeaf,
		members:           next,
		context:           context,
		secrets:           secrets,
		interim:           interim(suite, confirmed, message.confirmationTag),
		encryptionPrivate: encryptionPrivate,
		signaturePrivate:  g.signaturePrivate,
	}
	pending := &PendingCommit{Message: message, Next: advanced}
	for _, a := range added {
		pending.Joiners = append(pending.Joiners, a.keyPackage)
	}
	if len(added) > 0 {
		if pending.Welcome, err = advanced.welcome(pending.Joiners, message.confirmationTag); err != nil {
			return nil, err
		}
	}
	return pending, nil
}

func (g *Group) groupInfoToBeSigned(tag []byte) []byte {
	w := writer{bytes: g.context.Encode()}
	w.raw(g.members.encode())
	w.vector(tag)
	w.uint32(g.ownLeaf)
	return w.bytes
}

func welcomeKeys(suite CipherSuite, welcomeSecret []byte) (key, nonce []byte) {
	return suite.ExpandWithLabel(welcomeSecret, "key", nil, suite.aeadKeyLength()),
		suite.ExpandWithLabel(welcomeSecret, "nonce", nil, aeadNonceLength)
}

func (g *Group) welcome(packages []*KeyPackage, tag []byte) (*Welcome, error) {
	suite := g.CipherSuite()
	tbs := g.groupInfoToBeSigned(tag)
	signature, err := suite.SignWithLabel(g.signaturePrivate, "GroupInfoTBS", tbs)
	if err != nil {
		return nil, err
	}
	info := writer{bytes: tbs}
	info.vector(signature)
	key, nonce := welcomeKeys(suite, g.secrets.WelcomeSecret)
	encrypted, err := aeadSeal(key, nonce, info.bytes)
	if err != nil {
		return nil, err
	}
	w := &Welcome{encryptedGroupInfo: encrypted}
	for _, k := range packages {
		sealed, err := suite.EncryptWithLabel(k.InitKey, "Welcome", encrypted, g.secrets.JoinerSecret)
		if err != nil {
			return nil, err
		}
		w.secrets = append(w.secrets, welcomeSecretEntry{k.Reference(), sealed})
	}
	return w, nil
}

// Process applies a commit somebody else made. It returns the next epoch, or
// removed when the commit removed this member, who can follow no further.
func (g *Group) Process(message *CommitMessage) (next *Group, removed bool, err error) {
	suite := g.CipherSuite()
	if !bytes.Equal(message.GroupID, g.GroupID()) {
		return nil, false, ErrWrongGroup
	}
	if message.Epoch != g.Epoch() {
		return nil, false, fmt.Errorf("%w: expected %d, got %d", ErrWrongEpoch, g.Epoch(), message.Epoch)
	}
	sender := g.members.leaf(message.Sender)
	if message.Sender == g.ownLeaf || sender == nil {
		return nil, false, fmt.Errorf("%w: leaf %d", ErrUnknownSender, message.Sender)
	}
	if !suite.VerifyWithLabel(sender.SignatureKey, "FramedContentTBS", append(g.context.Encode(), message.content()...), message.signature) {
		return nil, false, fmt.Errorf("%w: commit", ErrBadSignature)
	}
	body, err := decodeCommitBody(message.commit)
	if err != nil {
		return nil, false, err
	}
	// A committer cannot remove itself: a member leaving is removed by
	// somebody who stays, so that the new secret has someone to come from.
	for _, p := range body.proposals {
		if p.add == nil && p.remove == message.Sender {
			return nil, false, fmt.Errorf("%w: committer removes itself", ErrInvalidProposal)
		}
	}
	if len(body.encryptionKey) != suite.PublicKeyLength() {
		return nil, false, fmt.Errorf("%w: committer encryption key length", ErrMalformed)
	}
	m, _, err := g.members.apply(body.proposals, suite)
	if err != nil {
		return nil, false, err
	}
	if m.leaf(g.ownLeaf) == nil {
		return nil, true, nil
	}
	m[message.Sender] = &Leaf{Identity: sender.Identity, SignatureKey: sender.SignatureKey, EncryptionKey: body.encryptionKey}

	provisional := GroupContext{CipherSuite: suite, GroupID: g.GroupID(), Epoch: g.Epoch() + 1, TreeHash: m.hash(suite), ConfirmedTranscriptHash: g.context.ConfirmedTranscriptHash}
	index := slices.IndexFunc(body.secrets, func(s sealedSecret) bool { return s.leaf == g.ownLeaf })
	if index < 0 {
		return nil, false, ErrNotAddressed
	}
	commitSecret, err := suite.DecryptWithLabel(g.encryptionPrivate, "UpdatePathNode", provisional.Encode(), body.secrets[index].ciphertext)
	if err != nil {
		return nil, false, err
	}

	confirmed := g.confirmed(message.content(), message.signature)
	context := GroupContext{CipherSuite: suite, GroupID: g.GroupID(), Epoch: g.Epoch() + 1, TreeHash: m.hash(suite), ConfirmedTranscriptHash: confirmed}
	secrets := DeriveEpochSecrets(g.secrets.InitSecret, commitSecret, nil, context)
	tag := suite.mac(secrets.ConfirmationKey, confirmed)
	if !hmac.Equal(tag, message.confirmationTag) {
		return nil, false, ErrConfirmationMismatch
	}
	return &Group{
		ownLeaf:           g.ownLeaf,
		members:           m,
		context:           context,
		secrets:           secrets,
		interim:           interim(suite, confirmed, tag),
		encryptionPrivate: g.encryptionPrivate,
		signaturePrivate:  g.signaturePrivate,
	}, false, nil
}

// Join enters a group from a Welcome addressed to bundle's key package. The
// group must be in the key package's suite.
func Join(welcome *Welcome, bundle *KeyPackageBundle) (*Group, error) {
	suite := bundle.KeyPackage.CipherSuite
	reference := bundle.KeyPackage.Reference()
	index := slices.IndexFunc(welcome.secrets, func(s welcomeSecretEntry) bool { return bytes.Equal(s.reference, reference) })
	if index < 0 {
		return nil, ErrNotAddressed
	}
	joiner, err := suite.DecryptWithLabel(bundle.initPrivate, "Welcome", welcome.encryptedGroupInfo, welcome.secrets[index].ciphertext)
	if err != nil {
		return nil, err
	}
	key, nonce := welcomeKeys(suite, welcomeSecret(suite, joiner, nil))
	info, err := aeadOpen(key, nonce, welcome.encryptedGroupInfo)
	if err != nil {
		return nil, err
	}

	r := &reader{data: info}
	context, err := readGroupContext(r)
	if err != nil {
		return nil, err
	}
	if context.CipherSuite != suite {
		return nil, fmt.Errorf("%w: group %#04x, package %#04x", ErrCipherSuiteMismatch, uint16(context.CipherSuite), uint16(suite))
	}
	m := readMembers(r)
	tag := r.vector()
	signer := r.uint32()
	signature := r.vector()
	if err := r.finish(); err != nil {
		return nil, err
	}

	signerLeaf := m.leaf(signer)
	if signerLeaf == nil {
		return nil, fmt.Errorf("%w: GroupInfo signer %d", ErrUnknownSender, signer)
	}
	tbs := writer{bytes: context.Encode()}
	tbs.raw(m.encode())
	tbs.vector(tag)
	tbs.uint32(signer)
	if !suite.VerifyWithLabel(signerLeaf.SignatureKey, "GroupInfoTBS", tbs.bytes, signature) {
		return nil, fmt.Errorf("%w: GroupInfo", ErrBadSignature)
	}
	if !bytes.Equal(m.hash(suite), context.TreeHash) {
		return nil, fmt.Errorf("%w: member list", ErrConfirmationMismatch)
	}
	secrets := deriveFromJoiner(suite, joiner, nil, context.Encode())
	if !hmac.Equal(suite.mac(secrets.ConfirmationKey, context.ConfirmedTranscriptHash), tag) {
		return nil, ErrConfirmationMismatch
	}
	own := bundle.KeyPackage.leaf()
	ownLeaf := slices.IndexFunc(m, own.equal)
	if ownLeaf < 0 {
		return nil, ErrNotAddressed
	}
	return &Group{
		ownLeaf:           uint32(ownLeaf),
		members:           m,
		context:           context,
		secrets:           secrets,
		interim:           interim(suite, context.ConfirmedTranscriptHash, tag),
		encryptionPrivate: bundle.encryptionPrivate,
		signaturePrivate:  bundle.signaturePrivate,
	}, nil
}
