/// Proof-system-related constants.
///
/// label for the extra data field to be appended to the transcript during
/// initialization
pub(crate) const EXTRA_TRANSCRIPT_MSG_LABEL: &[u8] = b"extra info";

/// Keccak-256 have a 64 byte state size to accommodate two hash digests.
pub const KECCAK256_STATE_SIZE: usize = 64;

/// The number of input wires.
pub const GATE_WIDTH: usize = 4;
