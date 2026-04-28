//! Pure pairing-code + deep-link helpers. Platform-independent so their
//! tests run on any host.

// On non-Linux (CI macOS cross-build), the `views` module that consumes these
// helpers is `cfg(target_os = "linux")` and excluded — so from the binary's
// POV these helpers are unused. The unit tests still exercise them.
#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

/// Validate a pairing code: exactly 8 ASCII digits.
///
/// Per protocol-spec pairing: 8-digit codes, IP-bound, single-use,
/// constant-time-compared server-side. This is the client-side format check.
pub fn validate_pairing_code(code: &str) -> Result<(), PairingCodeError> {
    if code.len() != 8 {
        return Err(PairingCodeError::WrongLength(code.len()));
    }
    if !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(PairingCodeError::NonDigit);
    }
    Ok(())
}

/// Reasons a pairing code is invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum PairingCodeError {
    /// Length != 8.
    WrongLength(usize),
    /// Contains a non-digit character.
    NonDigit,
}

/// Parsed `sigilauth://pair?code=XXXXXXXX&server=https://...` deep link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeepLink {
    /// 8-digit pairing code.
    pub code: Option<String>,
    /// Server URL (`https://`).
    pub server: Option<String>,
}

/// Parse a `sigilauth://pair?code=...&server=...` URI into its query parts.
/// Returns `None` if the URI is not a `sigilauth://pair` link.
pub fn parse_deep_link(uri: &str) -> Option<DeepLink> {
    if !uri.starts_with("sigilauth://pair") {
        return None;
    }
    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut link = DeepLink {
        code: None,
        server: None,
    };
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "code" => link.code = url_decode(v),
            "server" => link.server = url_decode(v),
            _ => {}
        }
    }
    Some(link)
}

/// Percent-decode `application/x-www-form-urlencoded` — supports `%XX`
/// escapes and `+` for space.
pub fn url_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_nibble(bytes[i + 1])?;
                let lo = hex_nibble(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn validate_pairing_code_happy_path() {
        assert!(validate_pairing_code("12345678").is_ok());
        assert!(validate_pairing_code("00000000").is_ok());
    }

    #[test]
    fn validate_pairing_code_rejects_wrong_length() {
        assert_eq!(
            validate_pairing_code("1234567"),
            Err(PairingCodeError::WrongLength(7))
        );
        assert_eq!(
            validate_pairing_code("123456789"),
            Err(PairingCodeError::WrongLength(9))
        );
        assert_eq!(
            validate_pairing_code(""),
            Err(PairingCodeError::WrongLength(0))
        );
    }

    #[test]
    fn validate_pairing_code_rejects_non_digits() {
        assert_eq!(
            validate_pairing_code("1234567a"),
            Err(PairingCodeError::NonDigit)
        );
        assert_eq!(
            validate_pairing_code("12345-78"),
            Err(PairingCodeError::NonDigit)
        );
        assert_eq!(
            validate_pairing_code("abcdefgh"),
            Err(PairingCodeError::NonDigit)
        );
    }

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("hello").as_deref(), Some("hello"));
        assert_eq!(url_decode("a%20b").as_deref(), Some("a b"));
        assert_eq!(url_decode("a+b").as_deref(), Some("a b"));
        assert_eq!(
            url_decode("https%3A%2F%2Fsigil.example.com").as_deref(),
            Some("https://sigil.example.com")
        );
    }

    #[test]
    fn url_decode_rejects_malformed() {
        assert_eq!(url_decode("%ZZ"), None);
        assert_eq!(url_decode("%1"), None);
    }

    #[test]
    fn parse_deep_link_code_and_server() {
        let uri = "sigilauth://pair?code=12345678&server=https%3A%2F%2Fsigil.example.com";
        let link = parse_deep_link(uri).expect("valid scheme");
        assert_eq!(link.code.as_deref(), Some("12345678"));
        assert_eq!(link.server.as_deref(), Some("https://sigil.example.com"));
    }

    #[test]
    fn parse_deep_link_only_code() {
        let uri = "sigilauth://pair?code=12345678";
        let link = parse_deep_link(uri).expect("valid scheme");
        assert_eq!(link.code.as_deref(), Some("12345678"));
        assert_eq!(link.server, None);
    }

    #[test]
    fn parse_deep_link_wrong_scheme_rejected() {
        assert_eq!(parse_deep_link("https://example.com"), None);
        assert_eq!(parse_deep_link("sigilauth://other"), None);
        assert_eq!(parse_deep_link("sigilauth://"), None);
    }

    #[test]
    fn parse_deep_link_empty_query() {
        let link = parse_deep_link("sigilauth://pair").expect("base scheme matches");
        assert_eq!(link.code, None);
        assert_eq!(link.server, None);
    }
}
