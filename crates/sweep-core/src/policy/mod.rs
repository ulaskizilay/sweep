//! Path policy: what is protected, and what counts as evidence of ownership.

pub mod protected;

pub use protected::{
    match_identity, match_identity_normalized, match_root, match_root_normalized, ProtectedRoot,
    IDENTITY_DIRS, PROTECTED_ROOTS,
};
