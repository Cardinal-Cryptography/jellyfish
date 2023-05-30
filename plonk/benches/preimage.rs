use ark_bls12_377::{Bls12_377, Fr};
use jf_plonk::PlonkType;
use jf_plonk::{
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_primitives::{
    circuit::rescue::RescueNativeGadget,
    crhf::{FixedLengthRescueCRHF, CRHF},
};
use jf_relation::{Circuit, PlonkCircuit};

use criterion::{criterion_group, criterion_main, Criterion};

type CircuitField = Fr;

fn new_circuit(plonk_type: PlonkType) -> PlonkCircuit<CircuitField> {
    match plonk_type {
        PlonkType::TurboPlonk => PlonkCircuit::new_turbo_plonk(),
        PlonkType::UltraPlonk => PlonkCircuit::new_ultra_plonk(0),
    }
}

fn gen_preimage_circuit() -> Result<PlonkCircuit<CircuitField>, PlonkError> {
    let mut circuit = new_circuit(PlonkType::TurboPlonk);
    let preimage = Fr::from(7_u32);
    let expected_image: Fr =
        FixedLengthRescueCRHF::<Fr, 3, 1>::evaluate([preimage, 1.into(), 0.into()]).unwrap()[0];

    let preimage_var = circuit.create_variable(preimage).unwrap();
    assert_eq!(&preimage, &circuit.witness(preimage_var).unwrap());

    let image_var =
        RescueNativeGadget::<Fr>::rescue_sponge_with_padding(&mut circuit, &[preimage_var], 1)
            .unwrap()[0];

    assert_eq!(&expected_image, &circuit.witness(image_var).unwrap());
    let expected_image_var = circuit.create_public_variable(expected_image).unwrap();
    circuit
        .enforce_equal(expected_image_var, image_var)
        .unwrap();

    println!("num gates  {:?}", circuit.num_gates());
    println!("num vars   {:?}", circuit.num_vars());
    println!("num inputs {:?}", circuit.num_inputs());

    assert!(circuit
        .check_circuit_satisfiability(&[expected_image])
        .is_ok());
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}

fn preimage(c: &mut Criterion) {
    let rng = &mut jf_utils::test_rng();
    let cs = gen_preimage_circuit().unwrap();

    let max_degree = 10000;
    let srs = PlonkKzgSnark::<Bls12_377>::universal_setup_for_testing(max_degree, rng).unwrap();

    let (pk, _) = PlonkKzgSnark::<Bls12_377>::preprocess(&srs, &cs).unwrap();
    c.bench_function("preimage", |f| {
        f.iter(|| {
            let _ =
                PlonkKzgSnark::<Bls12_377>::prove::<_, _, StandardTranscript>(rng, &cs, &pk, None)
                    .unwrap();
        })
    });
}

criterion_group!(benches, preimage);
criterion_main!(benches);
