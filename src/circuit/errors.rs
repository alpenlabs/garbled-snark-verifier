use crate::GateError;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum CircuitError {
    #[error("Gate error: {0}")]
    Gate(#[from] GateError),
    #[error("Garbling failed: {0}")]
    GarblingFailed(String),
}
