use std::convert::TryFrom;
use std::ffi::CString;
use std::fmt;
use std::iter::Peekable;

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidScope { got: String, expected: String },
    InvalidType { got: String, expected: String },
    InvalidDelimiter,
    IncompleteRule,
    MapRuleViolation,
    NoRulesProvided,
}

impl std::error::Error for ErrorKind {}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Error {
    pub cause: ErrorKind,
    pub rule: Option<usize>,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<ErrorKind> for Error {
    fn from(ek: ErrorKind) -> Self {
        Self {
            cause: ek,
            rule: None,
        }
    }
}

bitflags::bitflags! {
    struct Scope: u8 {
        const CLIENT = 0b01;
        const SERVER = 0b10;
    }
}

impl Scope {
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, ErrorKind> {
        let bytes = bytes.as_ref();

        Ok(match &bytes[..] {
            b"all" => Scope::CLIENT | Scope::SERVER,
            b"client" => Scope::CLIENT,
            b"server" => Scope::SERVER,
            _ => {
                return Err(ErrorKind::InvalidScope {
                    got: String::from_utf8_lossy(bytes).into(),
                    expected: ["all", "client", "server"].join(", "),
                })
            }
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Type {
    Prefix,
    Okay,
    Bad,
    Map,
}

impl Type {
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, ErrorKind> {
        let bytes = bytes.as_ref();

        Ok(match &bytes[..] {
            b"prefix" => Type::Prefix,
            b"ok" => Type::Okay,
            b"bad" => Type::Bad,
            b"map" => Type::Map,
            _ => {
                return Err(ErrorKind::InvalidType {
                    got: String::from_utf8_lossy(bytes).into(),
                    expected: ["prefix", "ok", "bad", "map"].join(", "),
                })
            }
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Rule {
    scope: Scope,
    type_: Type,
    key: CString,
    prepend: CString,
}

impl Rule {
    fn from_tokens<I>(tokens: &mut Peekable<I>) -> Result<Self, ErrorKind>
    where
        I: Iterator<Item = char>,
    {
        // The caller has already trimmed the whitespace leading up to here,
        // so the next element should be a rule delimiter.
        let delim = tokens.next().ok_or(ErrorKind::InvalidDelimiter)?;

        // This exists instead of using take_while() because take_while() will
        // consume the delimiter (if it exists) and it won't complain if it doesn't
        // exist. That means that we wouldn't be able to check for an unterminated
        // rule error like this:
        //      :prefix:all:trusted.:user.vm.
        //                                   ^ missing ':'
        let mut next_token = || {
            let mut bytes = vec![];
            loop {
                if let Some(ch) = tokens.peek() {
                    if !ch.eq(&delim) {
                        bytes.push(*ch as u8);
                        let _ = tokens.next();
                    } else {
                        // advance past delimiter
                        let _ = tokens.next();
                        break;
                    }
                } else {
                    // Ran out of tokens without finding a terminating delimiter
                    return Err(ErrorKind::IncompleteRule);
                }
            }

            Ok(bytes)
        };

        let type_ = Type::from_bytes(&next_token()?)?;

        Ok(match type_ {
            Type::Map => Rule {
                type_,
                scope: Scope::CLIENT | Scope::SERVER,
                key: CString::new(next_token()?).unwrap(),
                prepend: CString::new(next_token()?).unwrap(),
            },
            Type::Prefix | Type::Okay | Type::Bad => {
                let scope = Scope::from_bytes(next_token()?)?;

                Rule {
                    type_,
                    scope,
                    key: CString::new(next_token()?).unwrap(),
                    prepend: CString::new(next_token()?).unwrap(),
                }
            }
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrMap {
    rules: Vec<Rule>,
}

impl TryFrom<&str> for XattrMap {
    type Error = Error;

    fn try_from(input: &str) -> Result<Self, Error> {
        let trimmed = input.trim();
        let mut unparsed = trimmed.chars().peekable();
        let mut rules: Vec<Rule> = vec![];

        while unparsed.peek().is_some() {
            // Skip any whitespace between rules
            if let Some(ch) = unparsed.peek() {
                if ch.is_ascii_whitespace() {
                    let _ = unparsed.next();
                    continue;
                }
            }

            let rule = Rule::from_tokens(&mut unparsed).map_err(|e| Error {
                cause: e,
                rule: Some(rules.len() + 1),
            })?;
            rules.push(rule);
        }

        if rules.is_empty() {
            return Err(ErrorKind::NoRulesProvided.into());
        }

        // There may only be one 'map' rule and it must be the final rule
        let last_idx = rules.len() - 1;
        let map_violation = rules
            .iter()
            .enumerate()
            .filter(|(i, r)| r.type_ == Type::Map && !i.eq(&last_idx))
            .map(|(i, _)| i + 1)
            .next();
        if let Some(idx) = map_violation {
            return Err(Error {
                rule: Some(idx),
                cause: ErrorKind::MapRuleViolation,
            });
        }

        Ok(Self { rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_can_parse_single_rule() {
        let input = ":prefix:client:trusted.:user.virtiofs.:";
        let actual = XattrMap::try_from(input).unwrap();
        let expected = XattrMap {
            rules: vec![Rule {
                type_: Type::Prefix,
                scope: Scope::CLIENT,
                key: CString::new("trusted.").unwrap(),
                prepend: CString::new("user.virtiofs.").unwrap(),
            }],
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parser_can_parse_multiple_valid_rules() {
        let input = ":prefix:all::user.virtiofs.::bad:all:::";
        let actual = XattrMap::try_from(input).unwrap();
        let expected = XattrMap {
            rules: vec![
                Rule {
                    type_: Type::Prefix,
                    scope: Scope::CLIENT | Scope::SERVER,
                    key: CString::new("").unwrap(),
                    prepend: CString::new("user.virtiofs.").unwrap(),
                },
                Rule {
                    type_: Type::Bad,
                    scope: Scope::CLIENT | Scope::SERVER,
                    key: CString::new("").unwrap(),
                    prepend: CString::new("").unwrap(),
                },
            ],
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parser_can_parse_rules_separated_by_whitespace() {
        let input = r#"
        /prefix/all/trusted./user.virtiofs./
        /bad/server//trusted./
        /bad/client/user.virtiofs.//
        /ok/all///
        "#;

        let actual = XattrMap::try_from(input).unwrap();
        let expected = XattrMap {
            rules: vec![
                Rule {
                    type_: Type::Prefix,
                    scope: Scope::CLIENT | Scope::SERVER,
                    key: CString::new("trusted.").unwrap(),
                    prepend: CString::new("user.virtiofs.").unwrap(),
                },
                Rule {
                    type_: Type::Bad,
                    scope: Scope::SERVER,
                    key: CString::new("").unwrap(),
                    prepend: CString::new("trusted.").unwrap(),
                },
                Rule {
                    type_: Type::Bad,
                    scope: Scope::CLIENT,
                    key: CString::new("user.virtiofs.").unwrap(),
                    prepend: CString::new("").unwrap(),
                },
                Rule {
                    type_: Type::Okay,
                    scope: Scope::CLIENT | Scope::SERVER,
                    key: CString::new("").unwrap(),
                    prepend: CString::new("").unwrap(),
                },
            ],
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parser_emits_incomplete_rule_error() {
        let input = ":prefix:client:hi";
        let actual = XattrMap::try_from(input).unwrap_err();
        let expected = Error {
            rule: Some(1),
            cause: ErrorKind::IncompleteRule,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parser_emits_error_when_multiple_map_rules_exist() {
        let input = ":map:trusted.:virtiofs.user.::map:trusted.:virtiofs.user.:";
        let actual = XattrMap::try_from(input).unwrap_err();
        let expected = Error {
            rule: Some(1),
            cause: ErrorKind::MapRuleViolation,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parser_emits_error_when_invalid_type_is_used() {
        let input = ":TOMATOPIRATE:trusted.:virtiofs.user.:";
        assert!(XattrMap::try_from(input).is_err());
    }

    #[test]
    fn test_parser_emits_error_when_invalid_scope_is_used() {
        let input = "/prefix/helloworld///";
        assert!(XattrMap::try_from(input).is_err());
    }

    #[test]
    fn test_parser_emits_error_when_no_rules_are_provided() {
        let input = " ";
        let actual = XattrMap::try_from(input).unwrap_err();
        let expected = Error {
            rule: None,
            cause: ErrorKind::NoRulesProvided,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_parser_can_parse_rules_with_different_delimiters() {
        let input = ":prefix:all:trusted.:user.virtiofs.: /prefix/all/trusted./user.virtiofs./";
        let expected_rule = Rule {
            type_: Type::Prefix,
            scope: Scope::CLIENT | Scope::SERVER,
            key: CString::new("trusted.").unwrap(),
            prepend: CString::new("user.virtiofs.").unwrap(),
        };
        let expected = XattrMap {
            rules: vec![expected_rule.clone(), expected_rule],
        };

        let actual = XattrMap::try_from(input).unwrap();
        assert_eq!(actual, expected);
    }
}
