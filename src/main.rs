mod eth;
mod transaction;

use crate::eth::submit;
use crate::transaction::create_init_counter_tx;
use arm::transaction::Transaction;

fn submit_transaction(transaction: Transaction) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let _ = rt.block_on(async { submit(transaction).await });
}
fn main() {
    let (tx, _, _) = create_init_counter_tx();
    submit_transaction(tx);
    println!("Hello, world!");
}
