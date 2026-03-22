//! Fast pattern and signature scanning for byte slices.
//!
//! Scan byte slices for patterns using IDA-style signatures or code-style
//! byte/mask pairs. Patterns with an exact byte prefix use a fast-path filter
//! that narrows candidates before verifying the full pattern.
//!
//! # Example
//!
//! ```
//! use procmod_scan::Pattern;
//!
//! let pattern = Pattern::from_ida("48 8B ? 89").unwrap();
//! let data = b"\x00\x48\x8B\xFF\x89\x00";
//! assert_eq!(pattern.scan_first(data), Some(1));
//! ```

mod error;
mod pattern;

pub use error::{Error, Result};
pub use pattern::{Pattern, Token};
