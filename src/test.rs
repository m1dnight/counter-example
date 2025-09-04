// use crate::eth::submit;
use crate::transaction::create_init_counter_tx;
use arm::compliance::ComplianceInstance;
use arm::compliance_unit::ComplianceUnit;
use arm::logic_proof::{LogicProver, LogicVerifier};
use arm::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use arm::resource::Resource;
use arm::transaction::Transaction;
use counter_library::counter_logic::CounterLogic;

/// Given a CounterLogic, returns its LogicProof
pub fn prove_counter_logic(counter_logic: CounterLogic) -> LogicVerifier {
    counter_logic.prove()
}

pub fn counter_logic_ref() -> Vec<u8> {
    CounterLogic::verifying_key_as_bytes()
}

// pub fn submit_transaction(transaction: Transaction) {
//     let rt = tokio::runtime::Builder::new_current_thread()
//         .enable_all()
//         .build()
//         .unwrap();

//     let _ = rt.block_on(async { submit(transaction).await });
// }

pub fn keypair() -> (
    (NullifierKey, NullifierKeyCommitment),
    (NullifierKey, NullifierKeyCommitment),
) {
    let x = NullifierKey::random_pair();
    let y = NullifierKey::random_pair();
    (x, y)
}

pub fn create_tx_in_rust(
    a: (NullifierKey, NullifierKeyCommitment),
    b: (NullifierKey, NullifierKeyCommitment),
) -> (
    Transaction,
    Resource,
    NullifierKey,
    ComplianceUnit,
    ComplianceInstance,
) {
    create_init_counter_tx(a, b)
}

pub fn delta_test(transaction: Transaction) -> (Vec<u8>, Vec<ComplianceInstance>, Vec<u8>) {
    let delta_message_tx = transaction.get_delta_msg();

    // list of instances
    let mut instances : Vec<ComplianceInstance> = Vec::new();

    let mut deltas: Vec<u8> = Vec::new();
    for action in transaction.actions {
        for unit in action.compliance_units {
            let instance = unit.get_instance();
            instances.push(instance.clone());
            deltas.append(&mut instance.delta_msg());
        }
    }
    (delta_message_tx, instances, deltas)
}


pub fn generate_delta_proof(transaction: Transaction) -> Transaction {
    let mut tx = transaction.clone();
    tx.generate_delta_proof();
    tx
}


pub fn delta_message(transaction : Transaction) -> Vec<u8> {
    transaction.get_delta_msg()
}