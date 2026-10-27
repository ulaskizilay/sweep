//! Path resolution helpers.

pub mod resolve;
pub mod xdg;

pub use resolve::{
    ancestors, depth, first_component, has_control_bytes, has_parent_component, is_within,
    join_component, normalize,
};
pub use xdg::{Xdg, XdgError};
