use crate::eth::submit;
use crate::transaction::{
    ephemeral_counter, generate_compliance_proof, generate_logic_proofs, init_counter_resource,
};
use arm::action::Action;
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::logic_proof::LogicProver;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use arm::transaction::{Delta, Transaction};
use arm::utils::words_to_bytes;
use counter_library::counter_logic::CounterLogic;
fn counter_logic_ref() -> Vec<u8> {
    CounterLogic::verifying_key_as_bytes()
}

fn submit_transaction(transaction: Transaction) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let _ = rt.block_on(async { submit(transaction).await });
}

fn test_rust() {
    let (ephemeral_counter, ephemeral_nf_key) = ephemeral_counter();
    let (counter_resource, counter_nf_key) =
        init_counter_resource(&ephemeral_counter, &ephemeral_nf_key);
    let (compliance_unit, rcv) = generate_compliance_proof(
        ephemeral_counter.clone(),
        ephemeral_nf_key.clone(),
        MerklePath::default(),
        counter_resource.clone(),
    );

    let logic_verifier_inputs = generate_logic_proofs(
        ephemeral_counter,
        ephemeral_nf_key,
        counter_resource.clone(),
    );

    let action = Action::new(vec![compliance_unit.clone()], logic_verifier_inputs);
    let delta_witness = DeltaWitness::from_bytes(&rcv);
    let mut tx = Transaction::create(vec![action], Delta::Witness(delta_witness.clone()));
    tx.generate_delta_proof();

    println!("{:?}", delta_witness);
}
fn test(compliance_unit: ComplianceUnit) {
    let initial_root = arm::compliance::INITIAL_ROOT.as_words().to_vec();
    let instance = compliance_unit.get_instance();
    let words = words_to_bytes(&instance.consumed_commitment_tree_root);
    println!("{:?}", instance);
    println!("{:?}", initial_root);
    println!("{:?}", compliance_unit);
    println!("{:?}", words);
}

fn keypair() -> (
    (NullifierKey, NullifierKeyCommitment),
    (NullifierKey, NullifierKeyCommitment),
) {
    let x = NullifierKey::random_pair();
    let y = NullifierKey::random_pair();
    (x, y)
}
