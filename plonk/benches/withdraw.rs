use ark_bls12_381::{Bls12_381, Fr};
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
    merkle_tree::{prelude::RescueMerkleTree, MerkleCommitment, MerkleTreeScheme},
};
use jf_relation::Circuit;
use jf_relation::PlonkCircuit;

use criterion::{criterion_group, criterion_main, Criterion};

type CircuitField = Fr;

fn compute_note(x1: Fr, x2: Fr, x3: Fr, x4: Fr) -> Fr {
    let input = [x1, x2, x3, x4, 0.into(), 0.into()];
    FixedLengthRescueCRHF::<Fr, 6, 1>::evaluate(input).unwrap()[0]
}

fn build_note_var(
    circuit: &mut PlonkCircuit<CircuitField>,
    token_id_var: usize,
    token_amount_var: usize,
    trapdoor_var: usize,
    nullifier_var: usize,
    expected_note_var: usize,
) -> usize {
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

    note_var
}

type MerkleTree = dyn MerkleTreeGadget<
    RescueMerkleTree<Fr>,
    MembershipProofVar = Merkle3AryMembershipProofVar,
    DigestGadget = RescueDigestGadget,
>;

fn build_merkle_proof(circuit: &mut PlonkCircuit<CircuitField>, elem: Fr) -> Fr {
    let uid = 0;
    let height = 16;

    let elements = vec![elem];
    let mt = RescueMerkleTree::from_elems(height, elements).unwrap();
    let expected_root = mt.commitment().digest();
    let (retrieved_elem, proof) = mt.lookup(uid).expect_ok().unwrap();
    assert_eq!(retrieved_elem, elem);

    let uid_var = circuit.create_variable(uid.into()).unwrap();
    let proof_var = MerkleTree::create_membership_proof_variable(circuit, &proof).unwrap();
    let root_var = MerkleTree::create_root_variable(circuit, expected_root).unwrap();
    MerkleTree::enforce_membership_proof(circuit, uid_var, proof_var, root_var).unwrap();

    expected_root
}

// Has 10 tokens and wants to take 7 out
//                                          merkle root
//                placeholder                                        x
//        1                          x                     x                         x
//   2        3                x          x            x       x                 x       x
// 4  *5*   6   7            x   x      x   x        x   x   x   x             x   x   x   x
#[allow(unused_variables)]
fn gen_withdraw_circuit() -> Result<PlonkCircuit<CircuitField>, PlonkError> {
    let mut circuit = PlonkCircuit::<CircuitField>::new_turbo_plonk();
    let token_id = Fr::from(0);
    let token_id_var = circuit.create_public_variable(token_id)?;

    // old note
    let whole_token_amount = Fr::from(10);
    let old_trapdoor = Fr::from(100);
    let old_nullifier = Fr::from(200);
    let old_note: Fr = compute_note(token_id, whole_token_amount, old_trapdoor, old_nullifier);

    let whole_token_amount_var: usize = circuit.create_variable(whole_token_amount)?;
    let old_trapdoor_var = circuit.create_variable(old_trapdoor)?;
    let expected_old_note_var = circuit.create_variable(old_note)?;
    let old_nullifier_var = circuit.create_public_variable(old_nullifier)?;

    let old_note_var = build_note_var(
        &mut circuit,
        token_id_var,
        whole_token_amount_var,
        old_trapdoor_var,
        old_nullifier_var,
        expected_old_note_var,
    );

    // new note
    let new_token_amount = Fr::from(3);
    let new_trapdoor = Fr::from(101);
    let new_nullifier = Fr::from(201);
    let new_note = compute_note(token_id, new_token_amount, new_trapdoor, new_nullifier);

    let new_token_amount_var = circuit.create_variable(new_token_amount)?;
    let new_trapdoor_var = circuit.create_variable(new_trapdoor)?;
    let new_nullifier_var = circuit.create_variable(new_nullifier)?;
    let expected_new_note_var = circuit.create_public_variable(new_note)?;

    let new_note_var = build_note_var(
        &mut circuit,
        token_id_var,
        whole_token_amount_var,
        new_trapdoor_var,
        new_nullifier_var,
        expected_new_note_var,
    );

    // token values
    let token_amount_out = Fr::from(7);
    let token_amount_out_var = circuit.create_public_variable(token_amount_out)?;
    let token_sum_var = circuit.add(token_amount_out_var, new_token_amount_var)?;
    circuit.enforce_equal(token_sum_var, whole_token_amount_var)?;

    // merkle proof
    let root = build_merkle_proof(&mut circuit, old_note);

    println!("num gates  {:?}", circuit.num_gates());
    println!("num vars   {:?}", circuit.num_vars());
    println!("num inputs {:?}", circuit.num_inputs());

    assert!(circuit
        .check_circuit_satisfiability(&[token_id, old_nullifier, new_note, token_amount_out, root])
        .is_ok());
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}

fn withdraw(c: &mut Criterion) {
    let rng = &mut jf_utils::test_rng();
    let cs = gen_withdraw_circuit().unwrap();

    let max_degree = 10000;
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(max_degree, rng).unwrap();

    let (pk, _) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &cs).unwrap();
    c.bench_function("withdraw", |f| {
        f.iter(|| {
            let _ =
                PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(rng, &cs, &pk, None)
                    .unwrap();
        })
    });
}

criterion_group!(benches, withdraw);
criterion_main!(benches);

// struct Withdraw {
//     // public
//     token_id: Fr,
//     old_nullifier: Fr,
//     new_note: Fr,
//     token_amount_out: Fr,
//     merkle_root: Fr,
//     // private
//     old_trapdoor: Fr,
//     new_trapdoor: Fr,
//     new_nullifier: Fr,
//     merkle_path: Vec<Fr>,
//     leaf_index: u64,
//     old_note: Fr,
//     whole_token_amount: Fr,
//     new_token_amount: Fr,
// }
