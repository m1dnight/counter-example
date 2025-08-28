use arm::action_tree::ACTION_TREE_DEPTH;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::{
    compliance_unit::ComplianceUnit,
    logic_proof::{LogicProver, LogicVerifier},
};

use counter_witness::CounterWitness;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct CounterLogic {
    witness: CounterWitness,
}

impl CounterLogic {
    pub fn new(
        is_consumed: bool,
        old_counter: Resource,
        old_counter_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        nf_key: NullifierKey,
        new_counter: Resource,
        new_counter_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    ) -> Self {
        Self {
            witness: CounterWitness {
                is_consumed,
                old_counter,
                old_counter_existence_path,
                nf_key,
                new_counter,
                new_counter_existence_path,
            },
        }
    }
}


impl LogicProver for CounterLogic {
    type Witness = CounterWitness;
    fn proving_key() -> &'static [u8] {
        SIMPLE_COUNTER_ELF
    }

    fn verifying_key() -> Digest {
        *SIMPLE_COUNTER_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}