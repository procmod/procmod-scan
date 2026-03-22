<p align="center">
<img src="logo.svg" width="256" height="256" alt="procmod-scan">
</p>

<h1 align="center">procmod-scan</h1>

<p align="center">Pattern and signature scanning with SIMD acceleration.</p>

---

Scan byte slices for patterns using IDA-style signatures or code-style byte/mask pairs. Zero dependencies. Designed to compose with [procmod-core](https://github.com/procmod/procmod-core) but works standalone on any `&[u8]`.

## Install

```toml
[dependencies]
procmod-scan = "1"
```

## Quick start

Find a function signature in a game's memory after an update moves everything around:

```rust
use procmod_scan::Pattern;

// the function starts with a known prologue, but the offset has changed
let sig = Pattern::from_ida("55 48 89 E5 48 83 EC ? 48 8B 3D").unwrap();

let code_section: &[u8] = /* read from process memory */;

if let Some(offset) = sig.scan_first(code_section) {
    println!("found function at base + {:#x}", offset);
}
```

## Usage

### IDA-style patterns

The most common format in game modding. Exact bytes as hex, `?` or `??` for wildcards:

```rust
use procmod_scan::Pattern;

let pattern = Pattern::from_ida("48 8B ? ? 89 05").unwrap();
let data = b"\x00\x48\x8B\xAA\xBB\x89\x05\x00";
assert_eq!(pattern.scan_first(data), Some(1));
```

### Code-style patterns

Byte array with a separate mask string. `x` for exact, `?` for wildcard:

```rust
use procmod_scan::Pattern;

let pattern = Pattern::from_code(
    b"\x55\x48\x89\xE5\x00\x00",
    "xxxx??"
).unwrap();
```

### Find all matches

`scan` returns every offset where the pattern matches, including overlapping matches:

```rust
use procmod_scan::Pattern;

let nop_sled = Pattern::from_ida("90 90 90").unwrap();
let data = b"\x90\x90\x90\x90";
assert_eq!(nop_sled.scan(data), vec![0, 1]);
```

### Composing with procmod-core

Read a module's memory and scan for a known signature to find a function after a game update:

```rust
use procmod_scan::Pattern;
// use procmod_core::Process;

fn find_damage_calc(/* process: &Process, */ module_bytes: &[u8]) -> Option<usize> {
    // damage calculation function signature - stable across patches
    let sig = Pattern::from_ida("48 89 5C 24 ? 57 48 83 EC 20 8B FA").unwrap();
    sig.scan_first(module_bytes)
}
```

## Performance

Patterns with an exact byte prefix (no leading wildcards) use a fast-path scan that filters candidate positions by the first byte before verifying the full pattern. This is the common case for real-world signatures and provides significant speedup on large memory regions.

For best performance, prefer patterns that start with exact bytes rather than wildcards.

## License

MIT
