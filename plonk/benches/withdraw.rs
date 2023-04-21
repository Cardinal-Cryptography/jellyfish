use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalSerialize, Compress};
use jf_plonk::{
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_primitives::{
    circuit::{
        merkle_tree::{Merkle3AryMembershipProofVar, MerkleTreeGadget, RescueDigestGadget},
        rescue::RescueNativeGadget,
    },
    crhf::{FixedLengthRescueCRHF, CRHF},
    merkle_tree::{
        prelude::RescueSparseMerkleTree, MerkleCommitment, MerkleTreeScheme,
        UniversalMerkleTreeScheme,
    },
};
use jf_relation::Circuit;
use jf_relation::PlonkCircuit;

use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;

type CircuitField = Fr;

fn compute_note(x1: Fr, x2: Fr, x3: Fr, x4: Fr) -> Fr {
    let input = [x1, x2, x3, x4, 0.into(), 0.into()];
    FixedLengthRescueCRHF::<Fr, 6, 1>::evaluate(input).unwrap()[0]
}

fn build_note_contraint(
    circuit: &mut PlonkCircuit<CircuitField>,
    token_id_var: usize,
    token_amount: Fr,
    trapdoor: Fr,
    nullifier: (Fr, bool),
    expected_note: (Fr, bool),
    max_var: usize,
) -> Result<usize, PlonkError> {
    let token_amount_var = circuit.create_variable(token_amount)?;
    circuit.enforce_lt(token_amount_var, max_var)?;

    let trapdoor_var = circuit.create_variable(trapdoor)?;

    let (nullifier, is_public) = nullifier;
    let nullifier_var = circuit.create_variable(nullifier)?;
    if is_public {
        circuit.set_variable_public(nullifier_var)?;
    }

    let (expected_note, is_public) = expected_note;
    let expected_note_var = circuit.create_variable(expected_note)?;
    if is_public {
        circuit.set_variable_public(expected_note_var)?;
    }

    let input: [usize; 6] = [
        token_id_var,
        token_amount_var,
        trapdoor_var,
        nullifier_var,
        circuit.zero(),
        circuit.zero(),
    ];
    let note_var = RescueNativeGadget::<Fr>::rescue_sponge_no_padding(circuit, input.as_slice(), 1)
        .unwrap()[0];
    circuit.enforce_equal(expected_note_var, note_var).unwrap();

    Ok(token_amount_var)
}

type MerkleTree = dyn MerkleTreeGadget<
    RescueSparseMerkleTree<BigUint, Fr>,
    MembershipProofVar = Merkle3AryMembershipProofVar,
    DigestGadget = RescueDigestGadget,
>;

fn build_merkle_proof(circuit: &mut PlonkCircuit<CircuitField>, elem: Fr) {
    let height = 11;
    let uid = BigUint::from(0u64);

    println!("height {}", height);
    let start = Instant::now();

    let mt = RescueSparseMerkleTree::from_kv_set(height as usize, &[(uid.clone(), elem)]).unwrap();
    println!("Building RSMT took {:?}", start.elapsed());

    let expected_root = mt.commitment().digest();
    let (retrieved_elem, proof) = mt.lookup(&uid).expect_ok().unwrap();
    assert_eq!(retrieved_elem, elem);
    assert!(mt.verify(&uid, proof.clone()).expect("succeed"));

    let uid_var = circuit.create_variable(uid.into()).unwrap();
    let proof_var = MerkleTree::create_membership_proof_variable(circuit, &proof).unwrap();
    let root_var = MerkleTree::create_root_variable(circuit, expected_root).unwrap();
    MerkleTree::enforce_membership_proof(circuit, uid_var, proof_var, root_var).unwrap();
}

fn gen_withdraw_circuit() -> Result<(PlonkCircuit<CircuitField>, Vec<Fr>), PlonkError> {
    let mut circuit = PlonkCircuit::<CircuitField>::new_turbo_plonk();
    let token_id = Fr::from(0);
    let token_id_var = circuit.create_public_variable(token_id)?;
    let max = Fr::from(u128::MAX);
    let max_var = circuit.create_variable(max)?;

    // old note
    let whole_token_amount = Fr::from(10);
    let old_trapdoor = Fr::from(100);
    let old_nullifier = Fr::from(200);
    let old_note: Fr = compute_note(token_id, whole_token_amount, old_trapdoor, old_nullifier);

    let whole_token_amount_var = build_note_contraint(
        &mut circuit,
        token_id_var,
        whole_token_amount,
        old_trapdoor,
        (old_nullifier, true),
        (old_note, false),
        max_var,
    )?;

    assert!(circuit
        .check_circuit_satisfiability(&[token_id, old_nullifier])
        .is_ok());

    // new note
    let new_token_amount = Fr::from(3);
    let new_trapdoor = Fr::from(101);
    let new_nullifier = Fr::from(201);
    let new_note = compute_note(token_id, new_token_amount, new_trapdoor, new_nullifier);

    let new_token_amount_var = build_note_contraint(
        &mut circuit,
        token_id_var,
        new_token_amount,
        new_trapdoor,
        (new_nullifier, false),
        (new_note, true),
        max_var,
    )?;

    assert!(circuit
        .check_circuit_satisfiability(&[token_id, old_nullifier, new_note])
        .is_ok());

    // token values
    let token_amount_out = Fr::from(7);
    let token_amount_out_var = circuit.create_public_variable(token_amount_out)?;
    circuit.enforce_lt(token_amount_out_var, max_var)?;
    let token_sum_var = circuit.add(token_amount_out_var, new_token_amount_var)?;
    circuit.enforce_equal(token_sum_var, whole_token_amount_var)?;

    assert!(circuit
        .check_circuit_satisfiability(&[token_id, old_nullifier, new_note, token_amount_out])
        .is_ok());

    // merkle proof
    build_merkle_proof(&mut circuit, old_note);

    println!("num gates  {:?}", circuit.num_gates());
    println!("num vars   {:?}", circuit.num_vars());
    println!("num inputs {:?}", circuit.num_inputs());

    assert!(circuit
        .check_circuit_satisfiability(&[token_id, old_nullifier, new_note, token_amount_out]) // root missing
        .is_ok());

    circuit.finalize_for_arithmetization()?;

    let public_input = vec![token_id, old_nullifier, new_note, token_amount_out];

    Ok((circuit, public_input))
}

fn withdraw(c: &mut Criterion) {
    let rng = &mut jf_utils::test_rng();
    let (cs, pi) = gen_withdraw_circuit().unwrap();

    let max_degree = 10000;
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(max_degree, rng).unwrap();

    c.bench_function("key_generation", |f| {
        f.iter(|| {
            PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &cs).unwrap();
        })
    });

    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &cs).unwrap();
    print_sizes("verify key", &vk);

    c.bench_function("prover", |f| {
        f.iter(|| {
            PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, &cs, &pk, None)
                .unwrap();
        })
    });

    let proof =
        PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, &cs, &pk, None).unwrap();
    print_sizes("proof", &proof);

    c.bench_function("verifier", |f| {
        f.iter(|| {
            PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(&vk, &pi, &proof, None)
                .unwrap();
        })
    });
}

fn print_sizes<T: CanonicalSerialize>(name: &str, obj: &T) {
    let mut buf_uncompressed = vec![0; obj.serialized_size(Compress::No)];
    obj.serialize_with_mode(&mut buf_uncompressed[..], Compress::No)
        .unwrap();
    let mut buf_compressed = vec![0; obj.serialized_size(Compress::Yes)];
    obj.serialize_with_mode(&mut buf_compressed[..], Compress::Yes)
        .unwrap();
    println!(
        "{} size is: {} {}",
        name,
        buf_uncompressed.len(),
        buf_compressed.len()
    );
}

criterion_group!(benches, withdraw);
criterion_main!(benches);
