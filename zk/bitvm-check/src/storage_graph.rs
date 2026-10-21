//! Presigned storage-bond transaction graph. All APIs are regtest prototypes.
//! The committee uses fresh two-party MuSig2 nonces for every input. Its signatures pin
//! every transition's inputs, outputs and timelocks. Commitment slots have NUMS internal
//! keys, so the provider cannot skip publishing a Winternitz assertion by key-path spending.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{
    rand::{thread_rng, RngCore},
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitvm::signatures::{Wots, Wots16, Wots32, Wots4};
use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
use std::collections::BTreeMap;
use std::str::FromStr;

pub const PROOF_COMMITMENTS: usize = 378;
pub const CHAIN_COMMITMENTS: usize = 3;
pub const SLOT_COUNT: usize = PROOF_COMMITMENTS + CHAIN_COMMITMENTS;
/// Optional extra commitment linking future compact certificates to the same provider term.
pub const TERM_JOURNAL_SLOT: usize = SLOT_COUNT;
pub const JOURNAL_SLOT_COUNT: usize = SLOT_COUNT + 1;
pub const BINDING_LEAF: usize = 364;
pub const MARKER_REFUND_LEAF: usize = 365;
pub const TREE_LEAVES: usize = 512;
const SIMPLE_FEE: u64 = 3_000;
const CHALLENGE_FEE: u64 = 60_000;
const COMMIT_FEES: [u64; 2] = [1_000_000, 500_000];
const SLASH_FEE: u64 = 2_000_000;

fn nums() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .unwrap()
}

pub struct Party {
    key: Keypair,
    pub x: XOnlyPublicKey,
}
impl Party {
    pub fn fresh() -> Self {
        let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::new(&mut thread_rng()));
        Self {
            x: key.x_only_public_key().0,
            key,
        }
    }
    pub fn output(&self, value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Address::p2tr(&Secp256k1::new(), self.x, None, Network::Regtest)
                .script_pubkey(),
        }
    }
}

pub struct Committee {
    parties: [Party; 2],
    context: KeyAggContext,
    pub x: XOnlyPublicKey,
}
impl Committee {
    pub fn fresh() -> Self {
        let parties = [Party::fresh(), Party::fresh()];
        let points = parties
            .iter()
            .map(|p| musig2::secp::Point::from_slice(&p.key.public_key().serialize()).unwrap())
            .collect::<Vec<_>>();
        let context = KeyAggContext::new(points).unwrap();
        let point: musig2::secp::Point = context.aggregated_pubkey();
        let x = XOnlyPublicKey::from_slice(&point.serialize()[1..]).unwrap();
        Self {
            parties,
            context,
            x,
        }
    }
    fn sign(&self, msg: [u8; 32]) -> Vec<u8> {
        let scalar = |i: usize| {
            musig2::secp::Scalar::from_slice(&self.parties[i].key.secret_bytes()).unwrap()
        };
        let mut nonce_a = [0u8; 32];
        let mut nonce_b = [0u8; 32];
        thread_rng().fill_bytes(&mut nonce_a);
        thread_rng().fill_bytes(&mut nonce_b);
        let mut first_a = FirstRound::new(
            self.context.clone(),
            nonce_a,
            0,
            SecNonceSpices::new()
                .with_seckey(scalar(0))
                .with_message(&msg),
        )
        .unwrap();
        let mut first_b = FirstRound::new(
            self.context.clone(),
            nonce_b,
            1,
            SecNonceSpices::new()
                .with_seckey(scalar(1))
                .with_message(&msg),
        )
        .unwrap();
        first_a
            .receive_nonce(1, first_b.our_public_nonce())
            .unwrap();
        first_b
            .receive_nonce(0, first_a.our_public_nonce())
            .unwrap();
        let mut second_a = first_a.finalize(scalar(0), msg).unwrap();
        let second_b = first_b.finalize(scalar(1), msg).unwrap();
        let share: PartialSignature = second_b.our_signature();
        second_a.receive_signature(1, share).unwrap();
        let signature: CompactSignature = second_a.finalize().unwrap();
        let bytes = signature.serialize();
        let check = bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes).unwrap();
        Secp256k1::verification_only()
            .verify_schnorr(&check, &Message::from_digest(msg), &self.x)
            .unwrap();
        bytes.to_vec()
    }
}

#[derive(Clone)]
pub struct State {
    pub spend: TaprootSpendInfo,
    pub script: ScriptBuf,
    pub output: ScriptBuf,
}
impl State {
    pub fn committee(x: XOnlyPublicKey) -> Self {
        Self::with_leaves(
            Builder::new()
                .push_x_only_key(&x)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            None,
        )
    }
    fn with_leaves(script: ScriptBuf, alternate: Option<ScriptBuf>) -> Self {
        let builder = match alternate {
            None => TaprootBuilder::new().add_leaf(0, script.clone()).unwrap(),
            Some(other) => TaprootBuilder::new()
                .add_leaf(1, script.clone())
                .unwrap()
                .add_leaf(1, other)
                .unwrap(),
        };
        let spend = builder.finalize(&Secp256k1::new(), nums()).unwrap();
        let output = ScriptBuf::new_p2tr_tweaked(spend.output_key());
        Self {
            spend,
            script,
            output,
        }
    }
    pub fn txout(&self, value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: self.output.clone(),
        }
    }
    fn finish(&self, mut stack: Vec<Vec<u8>>, script: &ScriptBuf) -> Witness {
        stack.push(script.to_bytes());
        stack.push(
            self.spend
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .unwrap()
                .serialize(),
        );
        Witness::from_slice(&stack)
    }
}

pub enum CommitmentKey {
    Bytes32(<Wots32 as Wots>::PublicKey),
    Bytes16(<Wots16 as Wots>::PublicKey),
    Bytes4(<Wots4 as Wots>::PublicKey),
}
impl CommitmentKey {
    fn slot(&self, committee: XOnlyPublicKey, client: XOnlyPublicKey, timeout: u16) -> State {
        let check = match self {
            Self::Bytes32(key) => Wots32::checksig_verify_and_clear_stack(key),
            Self::Bytes16(key) => Wots16::checksig_verify_and_clear_stack(key),
            Self::Bytes4(key) => Wots4::checksig_verify_and_clear_stack(key),
        };
        let head = Builder::new()
            .push_x_only_key(&committee)
            .push_opcode(OP_CHECKSIGVERIFY)
            .into_script();
        let mut commit_bytes = head.into_bytes();
        commit_bytes.extend_from_slice(check.compile().as_bytes());
        commit_bytes.push(OP_PUSHNUM_1.to_u8());
        let commit = ScriptBuf::from_bytes(commit_bytes);
        let timeout = Builder::new()
            .push_int(timeout as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&client)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        State::with_leaves(commit, Some(timeout))
    }
}

/// A full tree commits all 364 real Groth16 leaves, the storage binding, and provider refund.
/// Hidden nodes retain hashes rather than gigabytes of scripts; the chosen disprove is revealed later.
pub struct ProofTree {
    pub hashes: Vec<TapNodeHash>,
    refund: ScriptBuf,
    pub marker: State,
}
impl ProofTree {
    pub fn new(
        mut proof_hashes: Vec<TapNodeHash>,
        binding: &ScriptBuf,
        provider: XOnlyPublicKey,
        window: u16,
    ) -> Self {
        assert_eq!(proof_hashes.len(), BINDING_LEAF);
        assert!(window > 0);
        proof_hashes.push(TapNodeHash::from_script(binding, LeafVersion::TapScript));
        let refund = Builder::new()
            .push_int(window as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&provider)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        proof_hashes.push(TapNodeHash::from_script(&refund, LeafVersion::TapScript));
        while proof_hashes.len() < TREE_LEAVES {
            let unused = Builder::new()
                .push_opcode(OP_RETURN)
                .push_int(proof_hashes.len() as i64)
                .into_script();
            proof_hashes.push(TapNodeHash::from_script(&unused, LeafVersion::TapScript));
        }
        let spend = Self::build(&proof_hashes, MARKER_REFUND_LEAF, &refund);
        let marker = State {
            output: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
            spend,
            script: refund.clone(),
        };
        Self {
            hashes: proof_hashes,
            refund,
            marker,
        }
    }
    fn build(hashes: &[TapNodeHash], index: usize, script: &ScriptBuf) -> TaprootSpendInfo {
        assert_eq!(hashes.len(), TREE_LEAVES);
        assert_eq!(
            hashes[index],
            TapNodeHash::from_script(script, LeafVersion::TapScript)
        );
        let mut builder = TaprootBuilder::new();
        for (i, hash) in hashes.iter().enumerate() {
            builder = if i == index {
                builder.add_leaf(9, script.clone()).unwrap()
            } else {
                builder.add_hidden_node(9, *hash).unwrap()
            };
        }
        builder.finalize(&Secp256k1::new(), nums()).unwrap()
    }
    pub fn disprove_witness(
        &self,
        index: usize,
        script: &ScriptBuf,
        stack: Vec<Vec<u8>>,
    ) -> Witness {
        assert!(index < MARKER_REFUND_LEAF);
        let spend = Self::build(&self.hashes, index, script);
        assert_eq!(spend.output_key(), self.marker.spend.output_key());
        State {
            spend,
            script: script.clone(),
            output: self.marker.output.clone(),
        }
        .finish(stack, script)
    }
}

#[derive(Clone, Copy)]
pub struct GraphConfig {
    pub term_end: u32,
    pub kickoff_deadline: u32,
    pub final_deadline: u32,
    pub challenge_blocks: u16,
    pub assert_blocks: u16,
    pub dispute_blocks: u16,
    pub slot_value: u64,
    pub marker_value: u64,
}
impl GraphConfig {
    pub fn validate(&self, funding: u64) {
        self.validate_slots(funding, SLOT_COUNT);
    }
    pub fn validate_slots(&self, funding: u64, slot_count: usize) {
        assert!(slot_count == SLOT_COUNT || slot_count == JOURNAL_SLOT_COUNT);
        assert!(self.term_end > 0 && self.kickoff_deadline > self.term_end);
        assert!(self.challenge_blocks > 0 && self.assert_blocks > 0 && self.dispute_blocks > 0);
        assert!(
            self.final_deadline
                > self.kickoff_deadline + self.assert_blocks as u32 + self.dispute_blocks as u32
        );
        assert!(self.slot_value >= 10_000 && self.marker_value >= 10_000);
        assert!(
            funding
                > self.slot_value * slot_count as u64
                    + COMMIT_FEES.iter().sum::<u64>()
                    + self.marker_value
                    + SLASH_FEE
                    + 100_000
        );
    }
}

pub struct GraphTx {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
}
impl GraphTx {
    fn new(inputs: Vec<(OutPoint, TxOut, Sequence)>, outputs: Vec<TxOut>, lock: u32) -> Self {
        let prevouts = inputs.iter().map(|(_, out, _)| out.clone()).collect();
        let input = inputs
            .into_iter()
            .map(|(previous_output, _, sequence)| TxIn {
                previous_output,
                sequence,
                script_sig: ScriptBuf::new(),
                witness: Witness::new(),
            })
            .collect();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::from_height(lock).unwrap(),
            input,
            output: outputs,
        };
        Self { tx, prevouts }
    }
    fn message(&self, index: usize, script: &ScriptBuf) -> [u8; 32] {
        SighashCache::new(&self.tx)
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(&self.prevouts),
                TapLeafHash::from_script(script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array()
    }
    fn committee_input(&mut self, index: usize, state: &State, committee: &Committee) {
        let sig = committee.sign(self.message(index, &state.script));
        self.tx.input[index].witness = state.finish(vec![sig], &state.script);
    }
    fn party_input(&mut self, index: usize, state: &State, who: &Party, script: &ScriptBuf) {
        let sig = Secp256k1::new().sign_schnorr_with_rng(
            &Message::from_digest(self.message(index, script)),
            &who.key,
            &mut thread_rng(),
        );
        self.tx.input[index].witness = state.finish(vec![sig.as_ref().to_vec()], script);
    }
    fn output(&self, index: usize) -> (OutPoint, TxOut) {
        (
            OutPoint::new(self.tx.compute_txid(), index as u32),
            self.tx.output[index].clone(),
        )
    }
}

pub struct StorageGraph {
    pub transactions: BTreeMap<String, GraphTx>,
    pub slots: Vec<State>,
    pub group_ranges: Vec<std::ops::Range<usize>>,
    pub slot_timeouts: Vec<GraphTx>,
    pub tree: ProofTree,
}

impl StorageGraph {
    pub fn build(
        config: GraphConfig,
        funding: OutPoint,
        amount: u64,
        committee: &Committee,
        provider: &Party,
        client: &Party,
        keys: &[CommitmentKey],
        tree: ProofTree,
    ) -> Self {
        let slot_count = keys.len();
        config.validate_slots(amount, slot_count);
        let root = State::committee(committee.x);
        let absolute = Sequence::ENABLE_LOCKTIME_NO_RBF;
        let mut transactions = BTreeMap::new();
        let mut kickoff = GraphTx::new(
            vec![(funding, root.txout(amount), absolute)],
            vec![root.txout(amount - SIMPLE_FEE)],
            config.term_end,
        );
        kickoff.committee_input(0, &root, committee);
        let mut kickoff_timeout = GraphTx::new(
            vec![(funding, root.txout(amount), absolute)],
            vec![client.output(amount - SIMPLE_FEE)],
            config.kickoff_deadline,
        );
        kickoff_timeout.committee_input(0, &root, committee);
        let (kickpoint, kickout) = kickoff.output(0);
        let mut unchallenged = GraphTx::new(
            vec![(
                kickpoint,
                kickout.clone(),
                Sequence::from_height(config.challenge_blocks),
            )],
            vec![provider.output(kickout.value.to_sat() - SIMPLE_FEE)],
            0,
        );
        unchallenged.committee_input(0, &root, committee);

        let slots: Vec<_> = keys
            .iter()
            .map(|key| key.slot(committee.x, client.x, config.assert_blocks))
            .collect();
        let control =
            kickout.value.to_sat() - config.slot_value * slot_count as u64 - CHALLENGE_FEE;
        let mut challenge_outputs = vec![root.txout(control)];
        challenge_outputs.extend(slots.iter().map(|s| s.txout(config.slot_value)));
        let mut challenge = GraphTx::new(
            vec![(kickpoint, kickout, Sequence::ZERO)],
            challenge_outputs,
            0,
        );
        challenge.committee_input(0, &root, committee);
        let (controlpoint, controlout) = challenge.output(0);
        let mut assert_timeout = GraphTx::new(
            vec![(
                controlpoint,
                controlout.clone(),
                Sequence::from_height(config.assert_blocks),
            )],
            vec![client.output(control - SIMPLE_FEE)],
            0,
        );
        assert_timeout.committee_input(0, &root, committee);

        let group_ranges = vec![0..300, 300..slot_count];
        let mut groups = Vec::new();
        let mut slot_timeouts = Vec::new();
        for (i, slot) in slots.iter().enumerate() {
            let (point, out) = challenge.output(i + 1);
            let timeout_script = Builder::new()
                .push_int(config.assert_blocks as i64)
                .push_opcode(OP_CSV)
                .push_opcode(OP_DROP)
                .push_x_only_key(&client.x)
                .push_opcode(OP_CHECKSIG)
                .into_script();
            let mut timeout = GraphTx::new(
                vec![(point, out, Sequence::from_height(config.assert_blocks))],
                vec![client.output(config.slot_value - 1_000)],
                0,
            );
            timeout.party_input(0, slot, client, &timeout_script);
            slot_timeouts.push(timeout);
        }
        for (group, range) in group_ranges.iter().enumerate() {
            let inputs = range
                .clone()
                .map(|i| {
                    let (p, o) = challenge.output(i + 1);
                    (p, o, Sequence::ZERO)
                })
                .collect();
            let value = range.len() as u64 * config.slot_value - COMMIT_FEES[group];
            let mut commit = GraphTx::new(inputs, vec![root.txout(value)], 0);
            for (input, slot) in range.clone().enumerate() {
                commit.committee_input(input, &slots[slot], committee);
            }
            groups.push(commit);
        }
        let mut final_inputs = vec![(controlpoint, controlout, Sequence::ZERO)];
        for group in &groups {
            let (p, o) = group.output(0);
            final_inputs.push((p, o, Sequence::ZERO));
        }
        let final_total: u64 = final_inputs
            .iter()
            .map(|(_, o, _)| o.value.to_sat())
            .sum::<u64>()
            - SIMPLE_FEE;
        let mut final_tx = GraphTx::new(
            final_inputs,
            vec![
                root.txout(final_total - config.marker_value),
                tree.marker.txout(config.marker_value),
            ],
            0,
        );
        for input in 0..final_tx.tx.input.len() {
            final_tx.committee_input(input, &root, committee);
        }
        let (mainpoint, mainout) = final_tx.output(0);
        let (markerpoint, markerout) = final_tx.output(1);
        let mut refund = GraphTx::new(
            vec![
                (mainpoint, mainout.clone(), Sequence::ZERO),
                (
                    markerpoint,
                    markerout.clone(),
                    Sequence::from_height(config.dispute_blocks),
                ),
            ],
            vec![provider.output(final_total - SIMPLE_FEE)],
            0,
        );
        refund.committee_input(0, &root, committee);
        refund.party_input(1, &tree.marker, provider, &tree.refund);
        let mut slash = GraphTx::new(
            vec![
                (mainpoint, mainout.clone(), Sequence::ZERO),
                (markerpoint, markerout, Sequence::ZERO),
            ],
            vec![client.output(final_total - SLASH_FEE)],
            0,
        );
        slash.committee_input(0, &root, committee);
        let mut final_timeout = GraphTx::new(
            vec![(mainpoint, mainout.clone(), absolute)],
            vec![client.output(mainout.value.to_sat() - SIMPLE_FEE)],
            config.final_deadline,
        );
        final_timeout.committee_input(0, &root, committee);
        for (name, tx) in [
            ("kickoff", kickoff),
            ("kickoff-timeout", kickoff_timeout),
            ("unchallenged-refund", unchallenged),
            ("challenge", challenge),
            ("assert-timeout", assert_timeout),
            ("assert-final", final_tx),
            ("refund", refund),
            ("slash", slash),
            ("final-timeout", final_timeout),
        ] {
            transactions.insert(name.to_owned(), tx);
        }
        let timeout_inputs = (0..slots.len())
            .map(|i| {
                let (p, o) = challenge_point_for_slots(&transactions["challenge"].tx, i);
                (p, o, Sequence::from_height(config.assert_blocks))
            })
            .collect();
        let mut timeout_all = GraphTx::new(
            timeout_inputs,
            vec![client.output(config.slot_value * slot_count as u64 - 150_000)],
            0,
        );
        for (i, slot) in slots.iter().enumerate() {
            let timeout_script = Builder::new()
                .push_int(config.assert_blocks as i64)
                .push_opcode(OP_CSV)
                .push_opcode(OP_DROP)
                .push_x_only_key(&client.x)
                .push_opcode(OP_CHECKSIG)
                .into_script();
            timeout_all.party_input(i, slot, client, &timeout_script);
        }
        transactions.insert("slots-timeout".to_owned(), timeout_all);
        for (i, tx) in groups.into_iter().enumerate() {
            transactions.insert(format!("assert-commit-{i}"), tx);
        }
        Self {
            transactions,
            slots,
            group_ranges,
            slot_timeouts,
            tree,
        }
    }
    pub fn attach_assertions(&mut self, signatures: &[Witness]) {
        assert_eq!(signatures.len(), self.slots.len());
        for (group, range) in self.group_ranges.iter().enumerate() {
            let tx = &mut self
                .transactions
                .get_mut(&format!("assert-commit-{group}"))
                .unwrap()
                .tx;
            let txid = tx.compute_txid();
            for (input, slot) in range.clone().enumerate() {
                let old: Vec<Vec<u8>> =
                    tx.input[input].witness.iter().map(|x| x.to_vec()).collect();
                assert_eq!(
                    old.len(),
                    3,
                    "committee signature plus script and control block"
                );
                let mut full: Vec<Vec<u8>> = signatures[slot].iter().map(|x| x.to_vec()).collect();
                full.extend(old);
                tx.input[input].witness = Witness::from_slice(&full);
            }
            assert_eq!(
                tx.compute_txid(),
                txid,
                "assertions may change witnesses only"
            );
        }
    }
    pub fn attach_disprove(&mut self, index: usize, script: &ScriptBuf, witness: Vec<Vec<u8>>) {
        self.transactions.get_mut("slash").unwrap().tx.input[1].witness =
            self.tree.disprove_witness(index, script, witness);
    }
}

fn challenge_point_for_slots(tx: &Transaction, index: usize) -> (OutPoint, TxOut) {
    (
        OutPoint::new(tx.compute_txid(), (index + 1) as u32),
        tx.output[index + 1].clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn committee_presignature_pins_both_inputs_payout_and_locktime() {
        let committee = Committee::fresh();
        let client = Party::fresh();
        let attacker = Party::fresh();
        let root = State::committee(committee.x);
        let first = OutPoint::null();
        let second = OutPoint::new(first.txid, 1);
        let mut tx = GraphTx::new(
            vec![
                (first, root.txout(10_000_000), Sequence::ZERO),
                (second, root.txout(1_000_000), Sequence::ZERO),
            ],
            vec![client.output(9_000_000)],
            220,
        );
        tx.committee_input(0, &root, &committee);
        let signature =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&tx.tx.input[0].witness[0]).unwrap();
        let verifies = |t: &GraphTx| {
            Secp256k1::verification_only()
                .verify_schnorr(
                    &signature,
                    &Message::from_digest(t.message(0, &root.script)),
                    &committee.x,
                )
                .is_ok()
        };
        assert!(verifies(&tx));
        tx.tx.input[1].witness.push([42u8]);
        assert!(
            verifies(&tx),
            "disprove witness is supplied after presigning"
        );
        tx.tx.output[0].script_pubkey = attacker.output(0).script_pubkey;
        assert!(!verifies(&tx), "cannot redirect a slash");
        tx.tx.output[0].script_pubkey = client.output(0).script_pubkey;
        tx.tx.input[1].previous_output.vout = 2;
        assert!(!verifies(&tx), "cannot replace the proof marker");
        tx.tx.input[1].previous_output.vout = 1;
        tx.tx.lock_time = LockTime::from_height(219).unwrap();
        assert!(!verifies(&tx), "cannot remove the term deadline");
    }
    #[test]
    fn streamed_tree_control_block_authenticates_the_exact_leaf() {
        let provider = Party::fresh();
        let false_script = Builder::new().push_int(0).into_script();
        let hashes = (0..364)
            .map(|i| {
                TapNodeHash::from_script(
                    &Builder::new()
                        .push_opcode(OP_RETURN)
                        .push_int(i)
                        .into_script(),
                    LeafVersion::TapScript,
                )
            })
            .collect();
        let tree = ProofTree::new(hashes, &false_script, provider.x, 6);
        let witness = tree.disprove_witness(BINDING_LEAF, &false_script, vec![]);
        let control = bitcoin::taproot::ControlBlock::decode(&witness[witness.len() - 1]).unwrap();
        assert_eq!(control.internal_key, nums());
        assert!(control.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            tree.marker.spend.output_key().to_x_only_public_key(),
            &false_script
        ));
        let altered = Builder::new().push_int(1).into_script();
        assert!(!control.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            tree.marker.spend.output_key().to_x_only_public_key(),
            &altered
        ));
    }
}
