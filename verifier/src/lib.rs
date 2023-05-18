// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use crate::{
    alloc::string::ToString,
    need::{
        BatchProof, PlonkError, PlookupProof, ProofEvaluations, SWToTEConParam,
        SnarkError::ParameterError, VerifyingKey,
    },
    transcript::PlonkTranscript,
    verifier::{Commitment, RescueParameter, Verifier},
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{format, vec, vec::Vec};

pub mod constants;
pub mod need;
pub mod transcript;
pub mod verifier;

pub fn verify<E, F, P, T>(
    verify_key: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    proof: &Proof<E>,
    extra_transcript_init_msg: Option<Vec<u8>>,
) -> Result<(), PlonkError>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
    T: PlonkTranscript<F>,
{
    batch_verify::<E, F, P, T>(
        &[verify_key],
        &[public_input],
        &[proof],
        &[extra_transcript_init_msg],
    )
}

/// Batch verify multiple SNARK proofs (w.r.t. different verifying keys).
pub fn batch_verify<E, F, P, T>(
    verify_keys: &[&VerifyingKey<E>],
    public_inputs: &[&[E::ScalarField]],
    proofs: &[&Proof<E>],
    extra_transcript_init_msgs: &[Option<Vec<u8>>],
) -> Result<(), PlonkError>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
    T: PlonkTranscript<F>,
{
    if public_inputs.len() != proofs.len()
        || verify_keys.len() != proofs.len()
        || extra_transcript_init_msgs.len() != proofs.len()
    {
        return Err(ParameterError(format!(
            "verify_keys.len: {}, public_inputs.len: {}, proofs.len: {}, \
                 extra_transcript_msg.len: {}",
            verify_keys.len(),
            public_inputs.len(),
            proofs.len(),
            extra_transcript_init_msgs.len()
        ))
        .into());
    }
    if verify_keys.is_empty() {
        return Err(ParameterError("the number of instances cannot be zero".to_string()).into());
    }

    let pcs_infos = parallelizable_slice_iter(verify_keys)
        .zip(parallelizable_slice_iter(proofs))
        .zip(parallelizable_slice_iter(public_inputs))
        .zip(parallelizable_slice_iter(extra_transcript_init_msgs))
        .map(|(((&vk, &proof), &pub_input), extra_msg)| {
            let verifier = Verifier::new(vk.domain_size)?;
            verifier.prepare_pcs_info::<T>(&[vk], &[pub_input], &(*proof).clone().into(), extra_msg)
        })
        .collect::<Result<Vec<_>, PlonkError>>()?;

    if !Verifier::batch_verify_opening_proofs::<T>(
        &verify_keys[0].open_key, // all open_key are the same
        &pcs_infos,
    )? {
        return Err(PlonkError::WrongProof);
    }
    Ok(())
}

/// A Plonk SNARK proof.
// #[tagged(tag::PROOF)]
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// Wire witness polynomials commitments.
    pub(crate) wires_poly_comms: Vec<Commitment<E>>,

    /// The polynomial commitment for the wire permutation argument.
    pub(crate) prod_perm_poly_comm: Commitment<E>,

    /// Splitted quotient polynomial commitments.
    pub(crate) split_quot_poly_comms: Vec<Commitment<E>>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub(crate) opening_proof: Commitment<E>,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub(crate) shifted_opening_proof: Commitment<E>,

    /// Polynomial evaluations.
    pub(crate) poly_evals: ProofEvaluations<E::ScalarField>,

    /// The partial proof for Plookup argument
    pub(crate) plookup_proof: Option<PlookupProof<E>>,
}

impl<E: Pairing> From<Proof<E>> for BatchProof<E> {
    fn from(proof: Proof<E>) -> Self {
        Self {
            wires_poly_comms_vec: vec![proof.wires_poly_comms],
            prod_perm_poly_comms_vec: vec![proof.prod_perm_poly_comm],
            poly_evals_vec: vec![proof.poly_evals],
            plookup_proofs_vec: vec![proof.plookup_proof],
            split_quot_poly_comms: proof.split_quot_poly_comms,
            opening_proof: proof.opening_proof,
            shifted_opening_proof: proof.shifted_opening_proof,
        }
    }
}

pub fn parallelizable_slice_iter<T>(data: &[T]) -> ark_std::slice::Iter<T> {
    data.iter()
}

pub struct StandardTranscript(merlin::Transcript);

impl<F> PlonkTranscript<F> for StandardTranscript {
    /// create a new plonk transcript
    fn new(label: &'static [u8]) -> Self {
        Self(merlin::Transcript::new(label))
    }

    // append the message to the transcript
    fn append_message(&mut self, label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        self.0.append_message(label, msg);

        Ok(())
    }

    // generate the challenge for the current transcript
    // and append it to the transcript
    fn get_and_append_challenge<E>(
        &mut self,
        label: &'static [u8],
    ) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing,
    {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label, &mut buf);
        let challenge = E::ScalarField::from_le_bytes_mod_order(&buf);
        self.0.append_message(label, &to_bytes!(&challenge)?);
        Ok(challenge)
    }
}
