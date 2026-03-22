use crate::error::{Error, Result};

/// A single element in a scan pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    /// Matches a specific byte value.
    Exact(u8),
    /// Matches any byte value.
    Wildcard,
}

/// A byte pattern used for scanning memory regions.
///
/// Patterns consist of exact byte matches and wildcard positions. They can be
/// constructed from IDA-style signature strings or code-style byte/mask pairs.
#[derive(Debug, Clone)]
pub struct Pattern {
    tokens: Vec<Token>,
}

impl Pattern {
    /// Creates a pattern from an IDA-style signature string.
    ///
    /// Each token is separated by whitespace. Exact bytes are specified as
    /// two-character hex values. Wildcards are represented by `?` or `??`.
    ///
    /// ```
    /// use procmod_scan::Pattern;
    ///
    /// let pattern = Pattern::from_ida("48 8B ?? 89 ? 0F").unwrap();
    /// ```
    pub fn from_ida(signature: &str) -> Result<Self> {
        let tokens = signature
            .split_whitespace()
            .map(|tok| match tok {
                "?" | "??" => Ok(Token::Wildcard),
                hex => {
                    if hex.len() != 2 {
                        return Err(Error::InvalidPattern(format!(
                            "expected 2-character hex token, got '{hex}'"
                        )));
                    }
                    u8::from_str_radix(hex, 16)
                        .map(Token::Exact)
                        .map_err(|_| Error::InvalidPattern(format!("invalid hex byte '{hex}'")))
                }
            })
            .collect::<Result<Vec<_>>>()?;

        if tokens.is_empty() {
            return Err(Error::InvalidPattern("pattern is empty".into()));
        }

        Ok(Self { tokens })
    }

    /// Creates a pattern from a code-style byte/mask pair.
    ///
    /// The mask string uses `x` for exact byte matches and `?` for wildcards,
    /// one character per byte. The mask length must equal the bytes length.
    ///
    /// ```
    /// use procmod_scan::Pattern;
    ///
    /// let pattern = Pattern::from_code(b"\x48\x8B\x00\x89", "xx?x").unwrap();
    /// ```
    pub fn from_code(bytes: &[u8], mask: &str) -> Result<Self> {
        if bytes.len() != mask.len() {
            return Err(Error::InvalidPattern(format!(
                "bytes length ({}) does not match mask length ({})",
                bytes.len(),
                mask.len()
            )));
        }

        if bytes.is_empty() {
            return Err(Error::InvalidPattern("pattern is empty".into()));
        }

        let tokens = bytes
            .iter()
            .zip(mask.chars())
            .map(|(&byte, m)| match m {
                'x' => Ok(Token::Exact(byte)),
                '?' => Ok(Token::Wildcard),
                other => Err(Error::InvalidPattern(format!(
                    "invalid mask character '{other}', expected 'x' or '?'"
                ))),
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { tokens })
    }

    /// Creates a pattern from raw tokens.
    ///
    /// Returns an error if the token list is empty.
    pub fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.is_empty() {
            return Err(Error::InvalidPattern("pattern is empty".into()));
        }
        Ok(Self { tokens })
    }

    /// Returns the tokens in this pattern.
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// Returns the number of tokens in this pattern.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns true if the pattern has no tokens.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Finds all offsets in `data` where this pattern matches.
    ///
    /// Returns an empty vec if no matches are found. Matches may overlap.
    pub fn scan(&self, data: &[u8]) -> Vec<usize> {
        if data.len() < self.tokens.len() {
            return Vec::new();
        }

        let prefix = exact_prefix(&self.tokens);

        if prefix.len() >= 2 {
            scan_prefix_filtered(data, &self.tokens, &prefix)
        } else {
            scan_naive(data, &self.tokens)
        }
    }

    /// Finds the first offset in `data` where this pattern matches.
    ///
    /// Returns `None` if no match is found.
    pub fn scan_first(&self, data: &[u8]) -> Option<usize> {
        if data.len() < self.tokens.len() {
            return None;
        }

        let prefix = exact_prefix(&self.tokens);

        if prefix.len() >= 2 {
            scan_first_prefix_filtered(data, &self.tokens, &prefix)
        } else {
            scan_first_naive(data, &self.tokens)
        }
    }
}

fn exact_prefix(tokens: &[Token]) -> Vec<u8> {
    tokens
        .iter()
        .take_while(|t| matches!(t, Token::Exact(_)))
        .map(|t| match t {
            Token::Exact(b) => *b,
            _ => unreachable!(),
        })
        .collect()
}

fn matches_at(data: &[u8], offset: usize, tokens: &[Token], skip: usize) -> bool {
    if offset + tokens.len() > data.len() {
        return false;
    }
    tokens[skip..].iter().enumerate().all(|(i, tok)| match tok {
        Token::Wildcard => true,
        Token::Exact(b) => data[offset + skip + i] == *b,
    })
}

fn scan_naive(data: &[u8], tokens: &[Token]) -> Vec<usize> {
    let end = data.len() - tokens.len() + 1;
    (0..end)
        .filter(|&i| matches_at(data, i, tokens, 0))
        .collect()
}

fn scan_first_naive(data: &[u8], tokens: &[Token]) -> Option<usize> {
    let end = data.len() - tokens.len() + 1;
    (0..end).find(|&i| matches_at(data, i, tokens, 0))
}

fn scan_prefix_filtered(data: &[u8], tokens: &[Token], prefix: &[u8]) -> Vec<usize> {
    let end = data.len() - tokens.len() + 1;
    let first = prefix[0];
    let skip = prefix.len();
    let mut results = Vec::new();

    let mut i = 0;
    while i < end {
        if let Some(pos) = memchr_single(first, &data[i..end]) {
            let abs = i + pos;
            if data[abs..].starts_with(prefix) && matches_at(data, abs, tokens, skip) {
                results.push(abs);
            }
            i = abs + 1;
        } else {
            break;
        }
    }

    results
}

fn scan_first_prefix_filtered(data: &[u8], tokens: &[Token], prefix: &[u8]) -> Option<usize> {
    let end = data.len() - tokens.len() + 1;
    let first = prefix[0];
    let skip = prefix.len();

    let mut i = 0;
    while i < end {
        if let Some(pos) = memchr_single(first, &data[i..end]) {
            let abs = i + pos;
            if data[abs..].starts_with(prefix) && matches_at(data, abs, tokens, skip) {
                return Some(abs);
            }
            i = abs + 1;
        } else {
            break;
        }
    }

    None
}

fn memchr_single(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ida_basic() {
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(
            p.tokens(),
            &[Token::Exact(0x48), Token::Exact(0x8B), Token::Exact(0x05)]
        );
    }

    #[test]
    fn ida_wildcards() {
        let p = Pattern::from_ida("48 ? ?? 89").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.tokens()[1], Token::Wildcard);
        assert_eq!(p.tokens()[2], Token::Wildcard);
    }

    #[test]
    fn ida_invalid_hex() {
        assert!(Pattern::from_ida("ZZ").is_err());
    }

    #[test]
    fn ida_invalid_length() {
        assert!(Pattern::from_ida("ABC").is_err());
    }

    #[test]
    fn ida_empty() {
        assert!(Pattern::from_ida("").is_err());
    }

    #[test]
    fn code_basic() {
        let p = Pattern::from_code(b"\x48\x8B\x00\x89", "xx?x").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.tokens()[2], Token::Wildcard);
        assert_eq!(p.tokens()[3], Token::Exact(0x89));
    }

    #[test]
    fn code_length_mismatch() {
        assert!(Pattern::from_code(b"\x48\x8B", "x").is_err());
    }

    #[test]
    fn code_invalid_mask() {
        assert!(Pattern::from_code(b"\x48", "z").is_err());
    }

    #[test]
    fn code_empty() {
        assert!(Pattern::from_code(b"", "").is_err());
    }

    #[test]
    fn scan_exact_match() {
        let data = b"\x00\x48\x8B\x05\x00\x00";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan(data), vec![1]);
    }

    #[test]
    fn scan_with_wildcards() {
        let data = b"\x48\x8B\xFF\x89\x00\x48\x8B\xAA\x89\x00";
        let p = Pattern::from_ida("48 8B ? 89").unwrap();
        assert_eq!(p.scan(data), vec![0, 5]);
    }

    #[test]
    fn scan_no_match() {
        let data = b"\x00\x00\x00\x00";
        let p = Pattern::from_ida("FF FF").unwrap();
        assert!(p.scan(data).is_empty());
    }

    #[test]
    fn scan_data_shorter_than_pattern() {
        let data = b"\x48";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert!(p.scan(data).is_empty());
    }

    #[test]
    fn scan_data_equals_pattern_length() {
        let data = b"\x48\x8B\x05";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan(data), vec![0]);
    }

    #[test]
    fn scan_first_found() {
        let data = b"\x00\x48\x8B\x05\x00\x48\x8B\x05";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan_first(data), Some(1));
    }

    #[test]
    fn scan_first_not_found() {
        let data = b"\x00\x00\x00";
        let p = Pattern::from_ida("FF").unwrap();
        assert_eq!(p.scan_first(data), None);
    }

    #[test]
    fn scan_overlapping() {
        let data = b"\xAA\xAA\xAA";
        let p = Pattern::from_ida("AA AA").unwrap();
        assert_eq!(p.scan(data), vec![0, 1]);
    }

    #[test]
    fn scan_all_wildcards() {
        let data = b"\x00\x01\x02\x03";
        let p = Pattern::from_ida("? ?").unwrap();
        assert_eq!(p.scan(data), vec![0, 1, 2]);
    }

    #[test]
    fn scan_single_byte_pattern() {
        let data = b"\x00\x90\x00\x90";
        let p = Pattern::from_ida("90").unwrap();
        assert_eq!(p.scan(data), vec![1, 3]);
    }

    #[test]
    fn scan_at_end_of_data() {
        let data = b"\x00\x00\x48\x8B";
        let p = Pattern::from_ida("48 8B").unwrap();
        assert_eq!(p.scan(data), vec![2]);
    }

    #[test]
    fn scan_empty_data() {
        let data: &[u8] = &[];
        let p = Pattern::from_ida("48").unwrap();
        assert!(p.scan(data).is_empty());
        assert_eq!(p.scan_first(data), None);
    }

    #[test]
    fn scan_long_prefix_uses_fast_path() {
        // pattern with 4-byte exact prefix should hit the simd-filtered path
        let mut data = vec![0u8; 4096];
        data[2000] = 0x48;
        data[2001] = 0x8B;
        data[2002] = 0x05;
        data[2003] = 0x10;
        data[2004] = 0xFF; // wildcard position

        let p = Pattern::from_ida("48 8B 05 10 ?").unwrap();
        assert_eq!(p.scan(&data), vec![2000]);
    }

    #[test]
    fn code_style_scan() {
        let data = b"\x00\x55\x48\x89\xE5\x00";
        let p = Pattern::from_code(b"\x55\x48\x00\xE5", "xx?x").unwrap();
        assert_eq!(p.scan(data), vec![1]);
    }

    #[test]
    fn from_tokens_works() {
        let p = Pattern::from_tokens(vec![
            Token::Exact(0x90),
            Token::Wildcard,
            Token::Exact(0xCC),
        ])
        .unwrap();
        let data = b"\x90\x00\xCC\x90\xFF\xCC";
        assert_eq!(p.scan(data), vec![0, 3]);
    }

    #[test]
    fn from_tokens_empty() {
        assert!(Pattern::from_tokens(vec![]).is_err());
    }

    #[test]
    fn ida_lowercase_hex() {
        let p = Pattern::from_ida("4a 8b ff").unwrap();
        assert_eq!(
            p.tokens(),
            &[Token::Exact(0x4A), Token::Exact(0x8B), Token::Exact(0xFF)]
        );
    }

    #[test]
    fn ida_mixed_case_hex() {
        let p = Pattern::from_ida("4A 8b Ff").unwrap();
        assert_eq!(
            p.tokens(),
            &[Token::Exact(0x4A), Token::Exact(0x8B), Token::Exact(0xFF)]
        );
    }

    #[test]
    fn scan_first_exact_length_match() {
        let data = b"\x48\x8B\x05";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan_first(data), Some(0));
    }

    #[test]
    fn scan_first_exact_length_no_match() {
        let data = b"\x48\x8B\x06";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan_first(data), None);
    }

    #[test]
    fn scan_wildcard_leading() {
        let data = b"\x00\x48\x8B\x00\x49\x8B";
        let p = Pattern::from_ida("? 8B").unwrap();
        assert_eq!(p.scan(data), vec![1, 4]);
    }

    #[test]
    fn scan_prefix_multiple_first_byte_one_full_match() {
        let data = b"\x48\x00\x00\x48\x8B\x05\x48\x00\x00";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan(data), vec![3]);
    }

    #[test]
    fn scan_prefix_all_candidates_match() {
        let data = b"\x48\x8B\x05\x00\x48\x8B\x05\x00";
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.scan(data), vec![0, 4]);
    }

    #[test]
    fn ida_extra_whitespace() {
        let p = Pattern::from_ida("  48   8B   05  ").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(
            p.tokens(),
            &[Token::Exact(0x48), Token::Exact(0x8B), Token::Exact(0x05)]
        );
    }
}
