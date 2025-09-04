use arm::compliance::ComplianceInstance;
use arm::compliance_unit::ComplianceUnit;
use arm::logic_proof::LogicVerifier;
use arm::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use arm::resource::Resource;
use arm::transaction::Transaction;
use counter_library::counter_logic::CounterLogic;
use crate::eth::submit;

mod eth;
mod test;
mod transaction;

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
    test::create_tx_in_rust(a, b)
}
fn counter_logic_ref() -> Vec<u8> {
    test::counter_logic_ref()
}

pub fn prove_counter_logic(counter_logic: CounterLogic) -> LogicVerifier {
    test::prove_counter_logic(counter_logic)
}

fn submit_transaction(transaction: arm::transaction::Transaction) {
    test::submit_transaction(transaction)
}

fn keypair() -> (
    (NullifierKey, NullifierKeyCommitment),
    (NullifierKey, NullifierKeyCommitment),
) {
    let x = NullifierKey::random_pair();
    let y = NullifierKey::random_pair();
    (x, y)
}

pub fn delta_message(transaction : Transaction) -> Vec<u8> {
    test::delta_message(transaction)
}

fn main() {
    let (a, b) = keypair();
    let tx = create_tx_in_rust(a, b);
    submit_transaction(tx.0);
    ()
}
