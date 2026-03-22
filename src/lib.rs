//! Pattern and signature scanning with SIMD acceleration.
//!
//! Scan byte slices for patterns using IDA-style signatures or code-style
//! byte/mask pairs. Exact byte prefixes are used as a fast filter before
//! verifying the full pattern at candidate positions.
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
