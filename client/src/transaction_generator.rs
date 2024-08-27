use {
    itertools::Itertools,
    rand::{
        distributions::{Alphanumeric, Distribution},
        SeedableRng,
    },
    solana_sdk::{
        compute_budget::ComputeBudgetInstruction,
        hash::Hash,
        instruction::{AccountMeta, Instruction},
        message::v0,
        pubkey::Pubkey,
        signature::Keypair,
        signer::Signer,
        transaction::VersionedTransaction,
    },
};

fn create_memo_tx(
    memo_program_id: Pubkey,
    msg: &[u8],
    payer: &Keypair,
    blockhash: Hash,
    cu_price_micro_lamports: u64,
) -> Vec<u8> {
    let accounts = (0..8).map(|_| Keypair::new()).collect_vec();
    let cu_budget_ix: Instruction =
        ComputeBudgetInstruction::set_compute_unit_price(cu_price_micro_lamports);
    let cu_limit_ix: Instruction = ComputeBudgetInstruction::set_compute_unit_limit(14000);

    let instruction = Instruction::new_with_bytes(
        memo_program_id,
        msg,
        accounts
            .iter()
            .map(|keypair| AccountMeta::new_readonly(keypair.pubkey(), true))
            .collect_vec(),
    );
    let message = v0::Message::try_compile(
        &payer.pubkey(),
        &[cu_budget_ix, cu_limit_ix, instruction],
        &[],
        blockhash,
    )
    .unwrap();
    let versioned_message = solana_sdk::message::VersionedMessage::V0(message);
    let mut signers = vec![payer];
    signers.extend(accounts.iter());

    let tx = VersionedTransaction::try_new(versioned_message, &signers).unwrap();
    bincode::serialize(&tx).unwrap()
}

fn generate_random_strings(
    num_of_txs: usize,
    random_seed: Option<u64>,
    n_chars: usize,
) -> Vec<Vec<u8>> {
    let seed = random_seed.map_or(0, |x| x);
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    (0..num_of_txs)
        .map(|_| Alphanumeric.sample_iter(&mut rng).take(n_chars).collect())
        .collect()
}

pub fn generate_transactions(count: usize, is_large: bool) -> Vec<Vec<u8>> {
    let blockhash = Hash::default();
    let payer_keypair = Keypair::new();
    let seed = 42;
    let size = if is_large { 232 } else { 5 };
    let random_strings = generate_random_strings(1, Some(seed), size);
    let rand_string = random_strings.first().unwrap();

    let memo_program_id = Pubkey::new_unique();
    (0..count)
        .map(|_| create_memo_tx(memo_program_id, rand_string, &payer_keypair, blockhash, 300))
        .collect_vec()
}

pub fn generate_dummy_data(size: usize) -> Vec<u8> {
    (0..size)
        .map(|x| (x % (u8::MAX as usize)) as u8)
        .collect_vec()
}
