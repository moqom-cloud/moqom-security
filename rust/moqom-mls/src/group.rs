// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Group membership: a deliberately small subset of MLS, the same as
//! MoqomMLS's `Group.swift`, which documents what it guarantees.
//!
//! No ratchet tree: members are a flat list of leaves, and a commit seals its
//! commit secret to every remaining member's leaf key directly, which is what
//! TreeKEM degenerates to when every parent node is blank. The GroupContext's
//! tree_hash is a hash of that list. Proposals are Add and Remove, carried by
//! value in the commit that applies them; an empty commit is an Update, which
//! refreshes the committer's leaf key.

use aws_lc_rs::constant_time;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hpke::AEAD_NONCE_LENGTH;
use crate::key_package::{KeyPackage, KeyPackageBundle};
use crate::key_schedule::{EpochSecrets, GroupContext, welcome_secret};
use crate::suite::{CipherSuite, HpkeCiphertext};

/// One member, as the group knows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// The MOQOM identity, username/device, as UTF-8.
    pub identity: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

impl Leaf {
    fn write(&self, w: &mut Writer) {
        w.vector(&self.identity);
        w.vector(&self.signature_key);
        w.vector(&self.encryption_key);
    }
}

/// The list of leaves, `None` where a member was removed.
type Members = Vec<Option<Leaf>>;

fn encode_members(members: &[Option<Leaf>]) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(members.len() as u32);
    for leaf in members {
        match leaf {
            None => w.u8(0),
            Some(leaf) => {
                w.u8(1);
                leaf.write(&mut w);
            }
        }
    }
    w.into_bytes()
}

fn read_members(r: &mut Reader<'_>) -> Result<Members> {
    let count = r.u32()?;
    if count > 1 << 16 {
        return Err(Error::Malformed("member count"));
    }
    (0..count)
        .map(|_| match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(Leaf {
                identity: r.vector()?.to_vec(),
                signature_key: r.vector()?.to_vec(),
                encryption_key: r.vector()?.to_vec(),
            })),
            _ => Err(Error::Malformed("leaf presence")),
        })
        .collect()
}

/// Fills the GroupContext's tree_hash slot. Not the RFC's tree hash, since
/// there is no tree.
fn members_hash(members: &[Option<Leaf>], suite: CipherSuite) -> Vec<u8> {
    suite.ref_hash("MOQOM 1.0 Member List", &encode_members(members))
}

fn leaf_at(members: &[Option<Leaf>], index: u32) -> Option<&Leaf> {
    members.get(index as usize).and_then(Option::as_ref)
}

#[derive(Clone)]
enum Proposal {
    Add(KeyPackage),
    Remove(u32),
}

impl Proposal {
    fn write(&self, w: &mut Writer) {
        match self {
            Self::Add(package) => {
                w.u16(1);
                w.vector(&package.encode());
            }
            Self::Remove(leaf) => {
                w.u16(3);
                w.u32(*leaf);
            }
        }
    }
}

/// Removes, then adds into the leftmost blank, then trims trailing blanks: in
/// that order on every member, which is what keeps leaf indices agreed without
/// sending them. Returns the new list and the leaves added.
fn apply(
    members: &[Option<Leaf>],
    proposals: &[Proposal],
    suite: CipherSuite,
) -> Result<(Members, Vec<(u32, KeyPackage)>)> {
    let mut next = members.to_vec();
    for proposal in proposals {
        if let Proposal::Remove(leaf) = proposal {
            if leaf_at(&next, *leaf).is_none() {
                return Err(Error::InvalidProposal("remove of an empty leaf"));
            }
            next[*leaf as usize] = None;
        }
    }
    let mut added = Vec::new();
    for proposal in proposals {
        let Proposal::Add(package) = proposal else {
            continue;
        };
        if package.cipher_suite != suite {
            return Err(Error::CipherSuiteMismatch {
                group: suite.0,
                key_package: package.cipher_suite.0,
            });
        }
        package.verify()?;
        if next.iter().flatten().any(|leaf| {
            leaf.signature_key == package.signature_key
                || leaf.encryption_key == package.encryption_key
                || leaf.identity == package.identity
        }) {
            return Err(Error::InvalidProposal("already a member"));
        }
        let slot = next.iter().position(Option::is_none).unwrap_or_else(|| {
            next.push(None);
            next.len() - 1
        });
        next[slot] = Some(package.leaf());
        added.push((slot as u32, package.clone()));
    }
    while matches!(next.last(), Some(None)) {
        next.pop();
    }
    Ok((next, added))
}

/// A commit, signed and confirmed, as it travels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitMessage {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: u32,
    commit: Vec<u8>,
    signature: Vec<u8>,
    confirmation_tag: Vec<u8>,
}

impl CommitMessage {
    /// The FramedContent: what is signed (after the GroupContext) and what the
    /// confirmed transcript hash covers (before the signature).
    fn content(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.vector(&self.group_id);
        w.u64(self.epoch);
        w.u32(self.sender);
        w.vector(&self.commit);
        w.into_bytes()
    }

    /// The message as it travels.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(self.content());
        w.vector(&self.signature);
        w.vector(&self.confirmation_tag);
        w.into_bytes()
    }

    /// Reads a commit's framing. The signature, the sealed secrets and the
    /// confirmation tag are checked by [`Group::process`].
    ///
    /// # Errors
    /// [`Error::Malformed`] if it does not decode.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader(data);
        let message = Self {
            group_id: r.vector()?.to_vec(),
            epoch: r.u64()?,
            sender: r.u32()?,
            commit: r.vector()?.to_vec(),
            signature: r.vector()?.to_vec(),
            confirmation_tag: r.vector()?.to_vec(),
        };
        r.finish()?;
        Ok(message)
    }
}

/// A commit's proposals, the committer's new leaf key (the whole of the "path"
/// here), and the commit secret sealed to each remaining member.
struct CommitBody {
    proposals: Vec<Proposal>,
    encryption_key: Vec<u8>,
    secrets: Vec<(u32, HpkeCiphertext)>,
}

impl CommitBody {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.proposals.len() as u32);
        for proposal in &self.proposals {
            proposal.write(&mut w);
        }
        w.vector(&self.encryption_key);
        w.u32(self.secrets.len() as u32);
        for (leaf, ciphertext) in &self.secrets {
            w.u32(*leaf);
            ciphertext.write(&mut w);
        }
        w.into_bytes()
    }

    fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader(data);
        let count = r.u32()?;
        if count > 1 << 12 {
            return Err(Error::Malformed("proposal count"));
        }
        let mut proposals = Vec::new();
        for _ in 0..count {
            match r.u16()? {
                1 => proposals.push(Proposal::Add(KeyPackage::decode(r.vector()?)?)),
                3 => proposals.push(Proposal::Remove(r.u32()?)),
                _ => return Err(Error::Unsupported("proposal type")),
            }
        }
        let encryption_key = r.vector()?.to_vec();
        let count = r.u32()?;
        if count > 1 << 16 {
            return Err(Error::Malformed("secret count"));
        }
        let secrets = (0..count)
            .map(|_| Ok((r.u32()?, HpkeCiphertext::read(&mut r)?)))
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(Self {
            proposals,
            encryption_key,
            secrets,
        })
    }
}

/// How a joiner enters: the joiner secret for each new member, and the group
/// as it now is, encrypted under the welcome secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    secrets: Vec<(Vec<u8>, HpkeCiphertext)>,
    encrypted_group_info: Vec<u8>,
}

impl Welcome {
    /// The Welcome as it travels.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.secrets.len() as u32);
        for (reference, ciphertext) in &self.secrets {
            w.vector(reference);
            ciphertext.write(&mut w);
        }
        w.vector(&self.encrypted_group_info);
        w.into_bytes()
    }

    /// Reads a Welcome.
    ///
    /// # Errors
    /// [`Error::Malformed`] if it does not decode.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader(data);
        let count = r.u32()?;
        if count > 1 << 16 {
            return Err(Error::Malformed("secret count"));
        }
        let secrets = (0..count)
            .map(|_| Ok((r.vector()?.to_vec(), HpkeCiphertext::read(&mut r)?)))
            .collect::<Result<_>>()?;
        let encrypted_group_info = r.vector()?.to_vec();
        r.finish()?;
        Ok(Self {
            secrets,
            encrypted_group_info,
        })
    }

    /// Whether the Welcome carries a secret for `key_package`.
    #[must_use]
    pub fn is_addressed_to(&self, key_package: &KeyPackage) -> bool {
        let reference = key_package.reference();
        self.secrets.iter().any(|(r, _)| *r == reference)
    }
}

/// A commit that has been built and not yet accepted. The group does not move
/// until the delivery service orders it first for its epoch; `next` is the
/// state to adopt when it does.
pub struct PendingCommit {
    pub message: CommitMessage,
    /// `None` when the commit adds nobody.
    pub welcome: Option<Welcome>,
    /// The key packages added, which are who the Welcome is for.
    pub joiners: Vec<KeyPackage>,
    pub next: Group,
}

/// What processing a commit did to this member.
pub enum Processed {
    /// The next epoch.
    Advanced(Box<Group>),
    /// The commit removed this member, who can follow no further.
    Removed,
}

/// One member's view of a group at one epoch. Every transition returns a new
/// `Group`; dropping the old one is what forward secrecy rests on.
#[derive(Clone)]
pub struct Group {
    own_leaf: u32,
    members: Members,
    context: GroupContext,
    secrets: EpochSecrets,
    interim: Vec<u8>,
    encryption_private: Vec<u8>,
    signature_private: Vec<u8>,
}

fn interim(suite: CipherSuite, confirmed: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut w = Writer::from(confirmed);
    w.vector(tag);
    suite.hash(&w.into_bytes())
}

fn welcome_keys(suite: CipherSuite, welcome_secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (
        suite.expand_with_label(welcome_secret, "key", &[], suite.aead().key_length()),
        suite.expand_with_label(welcome_secret, "nonce", &[], AEAD_NONCE_LENGTH),
    )
}

fn group_info_to_be_signed(
    context: &GroupContext,
    members: &[Option<Leaf>],
    tag: &[u8],
    signer: u32,
) -> Vec<u8> {
    let mut w = Writer(context.encode());
    w.raw(&encode_members(members));
    w.vector(tag);
    w.u32(signer);
    w.into_bytes()
}

impl Group {
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.context.group_id
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.context.epoch
    }

    /// The suite the group was founded in.
    #[must_use]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite
    }

    /// This member's leaf index.
    #[must_use]
    pub fn own_leaf(&self) -> u32 {
        self.own_leaf
    }

    /// The leaves by index, `None` where a member was removed.
    #[must_use]
    pub fn members(&self) -> &[Option<Leaf>] {
        &self.members
    }

    /// RFC 9420's epoch_authenticator: equal on every member's device for the
    /// same epoch, and something two people can compare to know nobody is in
    /// the group that the other cannot see.
    #[must_use]
    pub fn epoch_authenticator(&self) -> &[u8] {
        &self.secrets.epoch_authenticator
    }

    /// MLS-Exporter, RFC 9420 §8.5, for this epoch.
    #[must_use]
    pub fn exporter(&self, label: &str, context: &[u8], length: usize) -> Vec<u8> {
        self.secrets.exporter(label, context, length)
    }

    /// The leaf an identity occupies, if any.
    #[must_use]
    pub fn leaf_of(&self, identity: &str) -> Option<u32> {
        self.members
            .iter()
            .position(|leaf| {
                leaf.as_ref()
                    .is_some_and(|leaf| leaf.identity == identity.as_bytes())
            })
            .map(|i| i as u32)
    }

    fn confirmed(&self, content: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut w = Writer::from(&self.interim);
        w.raw(content);
        w.vector(signature);
        self.cipher_suite().hash(&w.into_bytes())
    }

    fn framed_content_tbs(&self, message: &CommitMessage) -> Vec<u8> {
        [self.context.encode(), message.content()].concat()
    }

    /// Starts a group with one member, in the suite of that member's key
    /// package.
    ///
    /// # Errors
    /// As [`KeyPackage::verify`].
    pub fn create(group_id: &[u8], bundle: &KeyPackageBundle) -> Result<Self> {
        bundle.key_package.verify()?;
        let suite = bundle.key_package.cipher_suite;
        let members = vec![Some(bundle.key_package.leaf())];
        let context = GroupContext {
            cipher_suite: suite,
            group_id: group_id.to_vec(),
            epoch: 0,
            tree_hash: members_hash(&members, suite),
            confirmed_transcript_hash: Vec::new(),
        };
        let secrets = EpochSecrets::derive(
            &suite.random_secret(),
            &suite.random_secret(),
            None,
            &context,
        );
        let tag = suite.mac(&secrets.confirmation_key, &[]);
        Ok(Self {
            own_leaf: 0,
            members,
            context,
            secrets,
            interim: interim(suite, &[], &tag),
            encryption_private: bundle.encryption_private.clone(),
            signature_private: bundle.signature_private.clone(),
        })
    }

    /// Builds a commit that adds and removes members and refreshes this
    /// member's leaf key. With nothing to add or remove it is a pure key
    /// rotation.
    ///
    /// # Errors
    /// [`Error::InvalidProposal`] for removing this member or an empty leaf,
    /// or adding a member twice; [`Error::CipherSuiteMismatch`] for a package
    /// in another suite; as [`KeyPackage::verify`] for a package that is not
    /// valid.
    pub fn commit(&self, adding: &[KeyPackage], removing: &[u32]) -> Result<PendingCommit> {
        let suite = self.cipher_suite();
        if removing.contains(&self.own_leaf) {
            return Err(Error::InvalidProposal("a committer cannot remove itself"));
        }
        let mut sorted = removing.to_vec();
        sorted.sort_unstable();
        let proposals: Vec<Proposal> = sorted
            .into_iter()
            .map(Proposal::Remove)
            .chain(adding.iter().cloned().map(Proposal::Add))
            .collect();
        let (mut next, added) = apply(&self.members, &proposals, suite)?;

        let (encryption_private, encryption_key) = suite.generate_key_pair()?;
        let own = next[self.own_leaf as usize]
            .as_mut()
            .expect("the committer stays");
        own.encryption_key.clone_from(&encryption_key);

        let commit_secret = suite.random_secret();
        let tree_hash = members_hash(&next, suite);
        let provisional = GroupContext {
            cipher_suite: suite,
            group_id: self.context.group_id.clone(),
            epoch: self.epoch() + 1,
            tree_hash: tree_hash.clone(),
            confirmed_transcript_hash: self.context.confirmed_transcript_hash.clone(),
        }
        .encode();
        let mut body = CommitBody {
            proposals,
            encryption_key,
            secrets: Vec::new(),
        };
        for (index, leaf) in next.iter().enumerate() {
            let index = index as u32;
            let Some(leaf) = leaf else { continue };
            if index == self.own_leaf || added.iter().any(|(slot, _)| *slot == index) {
                continue;
            }
            let sealed = suite.encrypt_with_label(
                &leaf.encryption_key,
                "UpdatePathNode",
                &provisional,
                &commit_secret,
            )?;
            body.secrets.push((index, sealed));
        }

        let mut message = CommitMessage {
            group_id: self.context.group_id.clone(),
            epoch: self.epoch(),
            sender: self.own_leaf,
            commit: body.encode(),
            signature: Vec::new(),
            confirmation_tag: Vec::new(),
        };
        message.signature = suite.sign_with_label(
            &self.signature_private,
            "FramedContentTBS",
            &self.framed_content_tbs(&message),
        )?;
        let confirmed = self.confirmed(&message.content(), &message.signature);
        let context = GroupContext {
            cipher_suite: suite,
            group_id: self.context.group_id.clone(),
            epoch: self.epoch() + 1,
            tree_hash,
            confirmed_transcript_hash: confirmed.clone(),
        };
        let secrets =
            EpochSecrets::derive(&self.secrets.init_secret, &commit_secret, None, &context);
        message.confirmation_tag = suite.mac(&secrets.confirmation_key, &confirmed);

        let advanced = Self {
            own_leaf: self.own_leaf,
            members: next,
            context,
            secrets,
            interim: interim(suite, &confirmed, &message.confirmation_tag),
            encryption_private,
            signature_private: self.signature_private.clone(),
        };
        let joiners: Vec<KeyPackage> = added.into_iter().map(|(_, package)| package).collect();
        let welcome = if joiners.is_empty() {
            None
        } else {
            Some(advanced.welcome(&joiners, &message.confirmation_tag)?)
        };
        Ok(PendingCommit {
            message,
            welcome,
            joiners,
            next: advanced,
        })
    }

    fn welcome(&self, packages: &[KeyPackage], tag: &[u8]) -> Result<Welcome> {
        let suite = self.cipher_suite();
        let tbs = group_info_to_be_signed(&self.context, &self.members, tag, self.own_leaf);
        let signature = suite.sign_with_label(&self.signature_private, "GroupInfoTBS", &tbs)?;
        let mut info = Writer(tbs);
        info.vector(&signature);
        let (key, nonce) = welcome_keys(suite, &self.secrets.welcome_secret);
        let encrypted_group_info = suite.aead().seal(&key, &nonce, &info.into_bytes())?;
        let secrets = packages
            .iter()
            .map(|package| {
                let sealed = suite.encrypt_with_label(
                    &package.init_key,
                    "Welcome",
                    &encrypted_group_info,
                    &self.secrets.joiner_secret,
                )?;
                Ok((package.reference(), sealed))
            })
            .collect::<Result<_>>()?;
        Ok(Welcome {
            secrets,
            encrypted_group_info,
        })
    }

    /// Applies a commit somebody else made.
    ///
    /// # Errors
    /// [`Error::WrongGroup`], [`Error::WrongEpoch`], [`Error::UnknownSender`],
    /// [`Error::BadSignature`], [`Error::InvalidProposal`],
    /// [`Error::NotAddressed`], [`Error::DecryptionFailed`] or
    /// [`Error::ConfirmationMismatch`], checked in that order.
    pub fn process(&self, message: &CommitMessage) -> Result<Processed> {
        let suite = self.cipher_suite();
        if message.group_id != self.context.group_id {
            return Err(Error::WrongGroup);
        }
        if message.epoch != self.epoch() {
            return Err(Error::WrongEpoch {
                expected: self.epoch(),
                got: message.epoch,
            });
        }
        let sender = match leaf_at(&self.members, message.sender) {
            Some(sender) if message.sender != self.own_leaf => sender.clone(),
            _ => return Err(Error::UnknownSender(message.sender)),
        };
        if !suite.verify_with_label(
            &sender.signature_key,
            "FramedContentTBS",
            &self.framed_content_tbs(message),
            &message.signature,
        ) {
            return Err(Error::BadSignature("commit"));
        }
        let body = CommitBody::decode(&message.commit)?;
        // A committer cannot remove itself: a member leaving is removed by
        // somebody who stays, so that the new secret has someone to come from.
        if body
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::Remove(leaf) if *leaf == message.sender))
        {
            return Err(Error::InvalidProposal("committer removes itself"));
        }
        if body.encryption_key.len() != suite.public_key_length() {
            return Err(Error::Malformed("committer encryption key length"));
        }
        let (mut members, _) = apply(&self.members, &body.proposals, suite)?;
        if leaf_at(&members, self.own_leaf).is_none() {
            return Ok(Processed::Removed);
        }
        members[message.sender as usize] = Some(Leaf {
            encryption_key: body.encryption_key.clone(),
            ..sender
        });

        let tree_hash = members_hash(&members, suite);
        let provisional = GroupContext {
            cipher_suite: suite,
            group_id: self.context.group_id.clone(),
            epoch: self.epoch() + 1,
            tree_hash: tree_hash.clone(),
            confirmed_transcript_hash: self.context.confirmed_transcript_hash.clone(),
        };
        let (_, sealed) = body
            .secrets
            .iter()
            .find(|(leaf, _)| *leaf == self.own_leaf)
            .ok_or(Error::NotAddressed)?;
        let commit_secret = suite.decrypt_with_label(
            &self.encryption_private,
            "UpdatePathNode",
            &provisional.encode(),
            sealed,
        )?;

        let confirmed = self.confirmed(&message.content(), &message.signature);
        let context = GroupContext {
            cipher_suite: suite,
            group_id: self.context.group_id.clone(),
            epoch: self.epoch() + 1,
            tree_hash,
            confirmed_transcript_hash: confirmed.clone(),
        };
        let secrets =
            EpochSecrets::derive(&self.secrets.init_secret, &commit_secret, None, &context);
        let tag = suite.mac(&secrets.confirmation_key, &confirmed);
        if constant_time::verify_slices_are_equal(&tag, &message.confirmation_tag).is_err() {
            return Err(Error::ConfirmationMismatch);
        }
        Ok(Processed::Advanced(Box::new(Self {
            own_leaf: self.own_leaf,
            members,
            context,
            secrets,
            interim: interim(suite, &confirmed, &tag),
            encryption_private: self.encryption_private.clone(),
            signature_private: self.signature_private.clone(),
        })))
    }

    /// Enters a group from a Welcome addressed to `bundle`'s key package. The
    /// group must be in the key package's suite.
    ///
    /// # Errors
    /// [`Error::NotAddressed`], [`Error::DecryptionFailed`],
    /// [`Error::CipherSuiteMismatch`], [`Error::BadSignature`] or
    /// [`Error::ConfirmationMismatch`].
    pub fn join(welcome: &Welcome, bundle: &KeyPackageBundle) -> Result<Self> {
        let suite = bundle.key_package.cipher_suite;
        let reference = bundle.key_package.reference();
        let (_, sealed) = welcome
            .secrets
            .iter()
            .find(|(r, _)| *r == reference)
            .ok_or(Error::NotAddressed)?;
        let joiner = suite.decrypt_with_label(
            &bundle.init_private,
            "Welcome",
            &welcome.encrypted_group_info,
            sealed,
        )?;
        let (key, nonce) = welcome_keys(suite, &welcome_secret(suite, &joiner, None));
        let info = suite
            .aead()
            .open(&key, &nonce, &welcome.encrypted_group_info)?;

        let mut r = Reader(&info);
        let context = GroupContext::read(&mut r)?;
        if context.cipher_suite != suite {
            return Err(Error::CipherSuiteMismatch {
                group: context.cipher_suite.0,
                key_package: suite.0,
            });
        }
        let members = read_members(&mut r)?;
        let tag = r.vector()?.to_vec();
        let signer = r.u32()?;
        let signature = r.vector()?;
        r.finish()?;

        let signer_leaf = leaf_at(&members, signer).ok_or(Error::UnknownSender(signer))?;
        let tbs = group_info_to_be_signed(&context, &members, &tag, signer);
        if !suite.verify_with_label(&signer_leaf.signature_key, "GroupInfoTBS", &tbs, signature) {
            return Err(Error::BadSignature("GroupInfo"));
        }
        if members_hash(&members, suite) != context.tree_hash {
            return Err(Error::ConfirmationMismatch);
        }
        let secrets = EpochSecrets::from_joiner(suite, joiner, None, &context.encode());
        let expected = suite.mac(
            &secrets.confirmation_key,
            &context.confirmed_transcript_hash,
        );
        if constant_time::verify_slices_are_equal(&expected, &tag).is_err() {
            return Err(Error::ConfirmationMismatch);
        }
        let own = bundle.key_package.leaf();
        let own_leaf = members
            .iter()
            .position(|leaf| leaf.as_ref() == Some(&own))
            .ok_or(Error::NotAddressed)?;
        Ok(Self {
            own_leaf: own_leaf as u32,
            interim: interim(suite, &context.confirmed_transcript_hash, &tag),
            members,
            context,
            secrets,
            encryption_private: bundle.encryption_private.clone(),
            signature_private: bundle.signature_private.clone(),
        })
    }
}
