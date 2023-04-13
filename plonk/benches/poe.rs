#![allow(dead_code)]
#![allow(unused_variables)]
// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench
// where N is the number of threads you want to use (N = 1 for single-thread).
use ark_bls12_377::Bls12_377;
use ark_ec::{
    pairing::Pairing,
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    AffineRepr, CurveConfig, CurveGroup,
};
use ark_ed_on_bls12_377::{EdwardsAffine, EdwardsConfig, Fr};
use ark_ff::PrimeField;
use ark_std::{rand::SeedableRng, UniformRand};
use jf_plonk::{
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_relation::{gadgets::ecc::Point, Arithmetization, Circuit, PlonkCircuit};
use jf_utils::fr_to_fq;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
const NUM_REPETITIONS: usize = 10;
const NUM_GATES_SMALL: usize = 8192;

const RANGE_BIT_LEN_FOR_TEST: usize = 8;

#[allow(non_snake_case)]
fn poe(c: &mut Criterion) {
    // set up the inputs and parameters
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let x = Fr::rand(&mut rng);
    let G = EdwardsAffine::generator();
    let X = (G * x).into_affine();

    // Our first step is to build a circuit for the following statements.
    // - secret input `x`;
    // - public generator `G`;
    // - public group element `X := xG`
    // This circuit does not need to have real inputs.
    // We can simply use a dummy data set.
    let circuit = proof_of_exponent_circuit::<EdwardsConfig, Bls12_377>(x, X).unwrap();
    println!(
        "metrics: {:?} {:?} {:?}",
        circuit.num_gates(),
        circuit.num_vars(),
        circuit.num_inputs()
    );

    // Knowing the circuit size, we are able to simulate the universal
    // setup and obtain the structured reference string (SRS).
    //
    // The required SRS size can be obtained from the circuit.
    let srs_size = circuit.srs_size().unwrap();
    let srs = PlonkKzgSnark::<Bls12_377>::universal_setup(srs_size, &mut rng).unwrap();

    // Then, we generate the proving key and verification key from the SRS and
    // circuit.
    let (pk, _) = PlonkKzgSnark::<Bls12_377>::preprocess(&srs, &circuit).unwrap();

    let start = Instant::now();

    c.bench_function("poe", |f| {
        f.iter(|| {
            let proof = PlonkKzgSnark::<Bls12_377>::prove::<_, _, StandardTranscript>(
                &mut rng, &circuit, &pk, None,
            )
            .unwrap();
        })
    });
}

criterion_group!(benches, poe);
criterion_main!(benches);

#[allow(non_snake_case)]
fn proof_of_exponent_circuit<EmbedCurve, PairingCurve>(
    x: EmbedCurve::ScalarField,
    X: TEAffine<EmbedCurve>,
) -> Result<PlonkCircuit<EmbedCurve::BaseField>, PlonkError>
where
    EmbedCurve: TECurveConfig,
    <EmbedCurve as CurveConfig>::BaseField: PrimeField,
    PairingCurve: Pairing,
{
    // Let's check that the inputs are indeed correct before we build a circuit.
    let G = TEAffine::<EmbedCurve>::generator();
    assert_eq!(X, G * x, "the inputs are incorrect: X != xG");

    // Step 1:
    // We instantiate a turbo plonk circuit.
    //
    // Here we only need turbo plonk since we are not using plookups.
    let mut circuit = PlonkCircuit::<EmbedCurve::BaseField>::new_turbo_plonk();

    // Step 2:
    // now we create variables for each input to the circuit.

    // First variable is x which is an field element over P::ScalarField.
    // We will need to lift it to P::BaseField.
    let x_fq = fr_to_fq::<_, EmbedCurve>(&x);
    let x_var = circuit.create_variable(x_fq)?;

    // The next variable is a public constant: generator `G`.
    // We need to convert the point to Jellyfish's own `Point` struct.
    let G_jf: Point<EmbedCurve::BaseField> = G.into();
    let G_var = circuit.create_constant_point_variable(G_jf)?;

    // The last variable is a public variable `X`.
    let X_jf: Point<EmbedCurve::BaseField> = X.into();
    let X_var = circuit.create_public_point_variable(X_jf)?;

    // Step 3:
    // Connect the wires.
    let X_var_computed = circuit.variable_base_scalar_mul::<EmbedCurve>(x_var, &G_var)?;
    circuit.enforce_point_equal(&X_var_computed, &X_var)?;

    // Sanity check: the circuit must be satisfied.
    assert!(circuit
        .check_circuit_satisfiability(&[X_jf.get_x(), X_jf.get_y()])
        .is_ok());

    // And we are done!
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}
