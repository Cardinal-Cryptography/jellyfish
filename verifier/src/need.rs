use crate::{
    alloc::string::ToString,
    need::SnarkError::{ParameterError, SnarkLookupUnsupported},
    verifier::Commitment,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup, VariableBaseMSM,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::String, vec, vec::Vec, Zero};
use displaydoc::Display;
use hashbrown::HashMap;

/// Preprocessed verifier parameters used to verify Plonk proofs for a certain
/// circuit.
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The size of the evaluation domain. Should be a power of two.
    pub(crate) domain_size: usize,

    /// The number of public inputs.
    pub(crate) num_inputs: usize,

    /// The permutation polynomial commitments. The commitments are not hiding.
    pub(crate) sigma_comms: Vec<Commitment<E>>,

    /// The selector polynomial commitments. The commitments are not hiding.
    pub(crate) selector_comms: Vec<Commitment<E>>,

    /// The constants K0, ..., K_num_wire_types that ensure wire subsets are
    /// disjoint.
    pub(crate) k: Vec<E::ScalarField>,

    /// KZG PCS opening key.
    pub open_key: OpenKey<E>,

    /// A flag indicating whether the key is a merged key.
    pub(crate) is_merged: bool,

    /// Plookup verifying key, None if not support lookup.
    pub(crate) plookup_vk: Option<PlookupVerifyingKey<E>>,
}

impl<E: Pairing> VerifyingKey<E> {
    /// Merge with another TurboPlonk verifying key to obtain a new TurboPlonk
    /// verifying key. Return error if any of the following holds:
    /// 1. the other verifying key has a different domain size;
    /// 2. the circuit underlying the other key has different number of inputs.
    /// 3. the key or the other key is not a TurboPlonk key.
    pub(crate) fn merge(&self, other_vk: &Self) -> Result<Self, PlonkError> {
        if self.is_merged || other_vk.is_merged {
            return Err(ParameterError("cannot merge a merged key again".to_string()).into());
        }
        if self.domain_size != other_vk.domain_size {
            return Err(ParameterError(
                "mismatched domain size when merging verifying keys".to_string(),
            )
            .into());
        }
        if self.num_inputs != other_vk.num_inputs {
            return Err(ParameterError(
                "mismatched number of public inputs when merging verifying keys".to_string(),
            )
            .into());
        }
        if self.plookup_vk.is_some() || other_vk.plookup_vk.is_some() {
            return Err(
                ParameterError("cannot merge UltraPlonk verifying keys".to_string()).into(),
            );
        }
        let sigma_comms: Vec<Commitment<E>> = self
            .sigma_comms
            .iter()
            .zip(other_vk.sigma_comms.iter())
            .map(|(com1, com2)| Commitment((com1.0 + com2.0).into_affine()))
            .collect();
        let selector_comms: Vec<Commitment<E>> = self
            .selector_comms
            .iter()
            .zip(other_vk.selector_comms.iter())
            .map(|(com1, com2)| Commitment((com1.0 + com2.0).into_affine()))
            .collect();

        Ok(Self {
            domain_size: self.domain_size,
            num_inputs: self.num_inputs + other_vk.num_inputs,
            sigma_comms,
            selector_comms,
            k: self.k.clone(),
            open_key: self.open_key,
            plookup_vk: None,
            is_merged: true,
        })
    }

    /// The lookup selector polynomial commitment
    pub(crate) fn q_lookup_comm(&self) -> Result<&Commitment<E>, PlonkError> {
        if self.plookup_vk.is_none() {
            return Err(SnarkLookupUnsupported.into());
        }
        Ok(self.selector_comms.last().unwrap())
    }
}

// Utility function for computing merged table evaluations.
#[inline]
pub(crate) fn eval_merged_table<E: Pairing>(
    tau: E::ScalarField,
    range_eval: E::ScalarField,
    key_eval: E::ScalarField,
    q_lookup_eval: E::ScalarField,
    w3_eval: E::ScalarField,
    w4_eval: E::ScalarField,
    table_dom_sep_eval: E::ScalarField,
) -> E::ScalarField {
    range_eval
        + q_lookup_eval
            * tau
            * (table_dom_sep_eval + tau * (key_eval + tau * (w3_eval + tau * w4_eval)))
}

// Utility function for computing merged lookup witness evaluations.
#[inline]
pub(crate) fn eval_merged_lookup_witness<E: Pairing>(
    tau: E::ScalarField,
    w_range_eval: E::ScalarField,
    w_0_eval: E::ScalarField,
    w_1_eval: E::ScalarField,
    w_2_eval: E::ScalarField,
    q_lookup_eval: E::ScalarField,
    q_dom_sep_eval: E::ScalarField,
) -> E::ScalarField {
    w_range_eval
        + q_lookup_eval
            * tau
            * (q_dom_sep_eval + tau * (w_0_eval + tau * (w_1_eval + tau * w_2_eval)))
}

/// A `enum` specifying the possible failure modes of the Plonk.
#[derive(Debug, Display)]
pub enum PlonkError {
    /// The index is too large for the universal public parameters
    IndexTooLarge,
    /// Failed to create domain
    DomainCreationError,
    /// Failed to get array value by index
    IndexError,
    /// Divided by zero field element
    DivisionError,
    /// An error in the Plonk SNARK logic: {0}
    SnarkError(SnarkError),
    /// An error in the underlying polynomial commitment
    PCSError,
    /// An error in the Plonk circuit
    CircuitError,
    /// An error during IO: {0}
    IoError(ark_std::io::Error),
    /// An error during (de)serialization
    SerializationError(ark_serialize::SerializationError),
    /// Plonk proof verification failed due to wrong proof
    WrongProof,
    /// Rescue Error
    PrimitiveError,
    /// Invalid parameters
    InvalidParameters(String),
    /// Non-native field overflow
    NonNativeFieldOverflow,
    /// Iterator out of range
    IteratorOutOfRange,
    /// Public inputs for partial verification circuit do not match
    PublicInputsDoNotMatch,
}

/// A `enum` specifying the possible failure modes of the underlying SNARK.
#[derive(Debug, Display)]
pub enum SnarkError {
    #[rustfmt::skip]
    /// Suspect: circuit is not satisfied. The quotient polynomial has wrong degree: {0}, expected: {1}.
    WrongQuotientPolyDegree(usize, usize),
    /// Invalid parameters: {0}
    ParameterError(String),
    /// The SNARK does not support lookup
    SnarkLookupUnsupported,
}

impl ark_std::error::Error for PlonkError {}

impl From<ark_std::io::Error> for PlonkError {
    fn from(e: ark_std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<ark_serialize::SerializationError> for PlonkError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}

impl From<SnarkError> for PlonkError {
    fn from(e: SnarkError) -> Self {
        Self::SnarkError(e)
    }
}

/// A simple wrapper of multi-pairing function.
pub fn multi_pairing<E>(g1_elems: &[E::G1Affine], g2_elems: &[E::G2Affine]) -> PairingOutput<E>
where
    E: Pairing,
{
    let (inputs_g1, inputs_g2): (Vec<E::G1Prepared>, Vec<E::G2Prepared>) = g1_elems
        .iter()
        .zip(g2_elems.iter())
        .map(|(g1, g2)| ((*g1).into(), (*g2).into()))
        .unzip();

    E::multi_pairing(inputs_g1, inputs_g2)
}

/// A Plookup argument proof.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlookupProof<E: Pairing> {
    /// The commitments for the polynomials that interpolate the sorted
    /// concatenation of the lookup table and the witnesses in the lookup gates.
    pub(crate) h_poly_comms: Vec<Commitment<E>>,

    /// The product accumulation polynomial commitment for the Plookup argument
    pub(crate) prod_lookup_poly_comm: Commitment<E>,

    /// Polynomial evaluations.
    pub(crate) poly_evals: PlookupEvaluations<E::ScalarField>,
}

/// A struct that stores the polynomial evaluations in a Plookup argument proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlookupEvaluations<F: Field> {
    /// Range table polynomial evaluation at point `zeta`.
    pub(crate) range_table_eval: F,

    /// Key table polynomial evaluation at point `zeta`.
    pub(crate) key_table_eval: F,

    /// Table domain separation polynomial evaluation at point `zeta`.
    pub(crate) table_dom_sep_eval: F,

    /// Domain separation selector polynomial evaluation at point `zeta`.
    pub(crate) q_dom_sep_eval: F,

    /// The first sorted vector polynomial evaluation at point `zeta`.
    pub(crate) h_1_eval: F,

    /// The lookup selector polynomial evaluation at point `zeta`.
    pub(crate) q_lookup_eval: F,

    /// Lookup product polynomial evaluation at point `zeta * g`.
    pub(crate) prod_next_eval: F,

    /// Range table polynomial evaluation at point `zeta * g`.
    pub(crate) range_table_next_eval: F,

    /// Key table polynomial evaluation at point `zeta * g`.
    pub(crate) key_table_next_eval: F,

    /// Table domain separation polynomial evaluation at point `zeta * g`.
    pub(crate) table_dom_sep_next_eval: F,

    /// The first sorted vector polynomial evaluation at point `zeta * g`.
    pub(crate) h_1_next_eval: F,

    /// The second sorted vector polynomial evaluation at point `zeta * g`.
    pub(crate) h_2_next_eval: F,

    /// The lookup selector polynomial evaluation at point `zeta * g`.
    pub(crate) q_lookup_next_eval: F,

    /// The 4th witness polynomial evaluation at point `zeta * g`.
    pub(crate) w_3_next_eval: F,

    /// The 5th witness polynomial evaluation at point `zeta * g`.
    pub(crate) w_4_next_eval: F,
}

impl<F: Field> PlookupEvaluations<F> {
    /// Return the list of evaluations at point `zeta`.
    pub(crate) fn evals_vec(&self) -> Vec<F> {
        vec![
            self.range_table_eval,
            self.key_table_eval,
            self.h_1_eval,
            self.q_lookup_eval,
            self.table_dom_sep_eval,
            self.q_dom_sep_eval,
        ]
    }

    /// Return the list of evaluations at point `zeta * g`.
    pub(crate) fn next_evals_vec(&self) -> Vec<F> {
        vec![
            self.prod_next_eval,
            self.range_table_next_eval,
            self.key_table_next_eval,
            self.h_1_next_eval,
            self.h_2_next_eval,
            self.q_lookup_next_eval,
            self.w_3_next_eval,
            self.w_4_next_eval,
            self.table_dom_sep_next_eval,
        ]
    }
}

/// The vector representation of bases and corresponding scalars.
#[derive(Debug)]
pub(crate) struct ScalarsAndBases<E: Pairing> {
    pub(crate) base_scalar_map: HashMap<E::G1Affine, E::ScalarField>,
}

impl<E: Pairing> ScalarsAndBases<E> {
    pub(crate) fn new() -> Self {
        Self {
            base_scalar_map: HashMap::new(),
        }
    }
    /// Insert a base point and the corresponding scalar.
    pub(crate) fn push(&mut self, scalar: E::ScalarField, base: E::G1Affine) {
        let entry_scalar = self
            .base_scalar_map
            .entry(base)
            .or_insert_with(E::ScalarField::zero);
        *entry_scalar += scalar;
    }

    /// Add a list of scalars and bases into self, where each scalar is
    /// multiplied by a constant c.
    pub(crate) fn merge(&mut self, c: E::ScalarField, scalars_and_bases: &Self) {
        for (base, scalar) in &scalars_and_bases.base_scalar_map {
            self.push(c * scalar, *base);
        }
    }
    /// Compute the multi-scalar multiplication.
    pub(crate) fn multi_scalar_mul(&self) -> E::G1 {
        let mut bases = vec![];
        let mut scalars = vec![];
        for (base, scalar) in &self.base_scalar_map {
            bases.push(*base);
            scalars.push(scalar.into_bigint());
        }
        VariableBaseMSM::msm_bigint(&bases, &scalars)
    }
}

/// This trait holds constants that are used for curve conversion from
/// short Weierstrass form to twisted Edwards form.
pub trait SWToTEConParam: PrimeField {
    /// Parameter S.
    const S: Self::BigInt;
    /// Parameter 1/alpha.
    const NEG_ALPHA: Self::BigInt;
    /// Parameter beta.
    const BETA: Self::BigInt;
}

/// A struct that stores the polynomial evaluations in a Plonk proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofEvaluations<F: Field> {
    /// Wire witness polynomials evaluations at point `zeta`.
    pub(crate) wires_evals: Vec<F>,

    /// Extended permutation (sigma) polynomials evaluations at point `zeta`.
    /// We do not include the last sigma polynomial evaluation.
    pub(crate) wire_sigma_evals: Vec<F>,

    /// Permutation product polynomial evaluation at point `zeta * g`.
    pub(crate) perm_next_eval: F,
}

/// An aggregated SNARK proof that batchly proving multiple instances.
// #[tagged(tag::BATCHPROOF)]
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchProof<E: Pairing> {
    /// The list of wire witness polynomials commitments.
    pub(crate) wires_poly_comms_vec: Vec<Vec<Commitment<E>>>,

    /// The list of polynomial commitment for the wire permutation argument.
    pub(crate) prod_perm_poly_comms_vec: Vec<Commitment<E>>,

    /// The list of polynomial evaluations.
    pub(crate) poly_evals_vec: Vec<ProofEvaluations<E::ScalarField>>,

    /// The list of partial proofs for Plookup argument
    pub(crate) plookup_proofs_vec: Vec<Option<PlookupProof<E>>>,

    /// Splitted quotient polynomial commitments.
    pub(crate) split_quot_poly_comms: Vec<Commitment<E>>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub(crate) opening_proof: Commitment<E>,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub(crate) shifted_opening_proof: Commitment<E>,
}

impl<E: Pairing> BatchProof<E> {
    /// The number of instances being proved in a batch proof.
    pub fn len(&self) -> usize {
        self.prod_perm_poly_comms_vec.len()
    }
    /// Check whether a BatchProof proves nothing.
    pub fn is_empty(&self) -> bool {
        self.prod_perm_poly_comms_vec.is_empty()
    }
}

/// `UnivariateVerifierParam` is used to check evaluation proofs for a given
/// commitment.
#[derive(CanonicalSerialize, CanonicalDeserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnivariateVerifierParam<E: Pairing> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
}

/// Key for verifying PCS opening proof.
pub type OpenKey<E> = UnivariateVerifierParam<E>;

/// Preprocessed verifier parameters used to verify Plookup proofs for a certain
/// circuit.
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlookupVerifyingKey<E: Pairing> {
    /// Range table polynomial commitment. The commitment is not hiding.
    pub(crate) range_table_comm: Commitment<E>,

    /// Key table polynomial commitment. The commitment is not hiding.
    pub(crate) key_table_comm: Commitment<E>,

    /// Table domain separation polynomial commitment. The commitment is not
    /// hiding.
    pub(crate) table_dom_sep_comm: Commitment<E>,

    /// Lookup domain separation selector polynomial commitment. The commitment
    /// is not hiding.
    pub(crate) q_dom_sep_comm: Commitment<E>,
}
