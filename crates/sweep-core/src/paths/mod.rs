//! Path resolution helpers.

pub mod resolve;
pub mod xdg;

pub use resolve::{
    ancestors, depth, first_component, has_control_bytes, has_parent_component, is_normalized,
    is_within, is_within_named, is_within_normalized, join_component, normalize, normalize_cow,
};
pub use xdg::{Xdg, XdgError};
