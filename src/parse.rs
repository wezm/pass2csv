use std::borrow::Cow;
use std::path::Path;

use hashlink::LinkedHashMap;
use url::{ParseError, Url};

use crate::{CreditCard, Login, Record, SecureNote, SoftwareLicence};

const SKIP_KEYS: &[&str] = &["^html", "^recaptcha", "commit", "op", "label"];
const SKIP_VALUES: &[&str] = &["✓", "SEND", "Y"];
const LOGIN_FIELDS: &[&str] = &[
    "*login",
    "*username",
    "*mail",
    "wpname",
    "membership no",
    "medicarecardnumber",
    "e",
];
const NOTE_FIELDS: &[&str] = &["comments", "customIcon", "predicate b64"];
const WEBSITE_FIELDS: &[&str] = &["location", "url", "website"];

#[derive(Debug)]
pub struct RawRecord<'a> {
    path: &'a Path,
    depth: usize,
    password: Option<&'a str>,
    fields: LinkedHashMap<Cow<'a, str>, &'a str>,
}

pub(crate) fn raw<'a>(path: &'a Path, depth: usize, item: &'a str) -> RawRecord<'a> {
    eprintln!("{}", path.display());
    if item.lines().count() == 1
        && item
            .lines()
            .next()
            .map_or(false, |line| !line.contains(": "))
    {
        return RawRecord {
            path,
            depth,
            password: Some(item.trim_end()),
            fields: LinkedHashMap::new(),
        };
    }

    // Probably a secure note
    const COMMENTS: &str = "comments: ";
    if item.split(':').count() == 2 || item.starts_with(COMMENTS) {
        let (key, value) = item.split_once(':').unwrap();
        if !key.contains('\n') {
            let mut fields = LinkedHashMap::new();
            fields.insert(Cow::from(key), value.trim_start());
            return RawRecord {
                path,
                depth,
                password: None,
                fields,
            };
        }
    }

    let mut fields = LinkedHashMap::new();
    let mut password = None;

    for line in item.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            let key = key.to_ascii_lowercase();
            if key.contains("pass")
                || key.contains("pwd")
                || key == "p"
                || key.starts_with("reg-pw")
            {
                // Use as password or skip if password is already set
                if password.is_none() {
                    password = Some(value.trim_start())
                }
            } else if value == "✓" {
                // skip
            } else {
                fields.insert(Cow::from(key), value.trim_start());
            }
        } else if password.is_none() {
            password = Some(line)
        } else if password.is_some() && fields.len() == 1 && fields.contains_key("comments") {
            // This is a secure note with a password, such as an ssh key
            let pos = item.find(COMMENTS).unwrap();
            let note = &item[pos + COMMENTS.len()..];
            fields.insert(Cow::from("comments"), note);
            return RawRecord {
                path,
                depth,
                password,
                fields,
            };
        } else {
            panic!(
                "error: malformed item: {:?}, {:?}: {}",
                password, fields, item
            );
        }
    }

    RawRecord {
        path,
        depth,
        password,
        fields,
    }
}

fn skip_key(key: &str) -> bool {
    key.is_empty() || SKIP_KEYS.iter().any(|&skip| matches(skip, key))
}

fn matches(pattern: &str, value: &str) -> bool {
    if pattern.starts_with('^') {
        value.starts_with(&pattern[1..])
    } else if pattern.starts_with('*') {
        value.contains(&pattern[1..])
    } else {
        value == pattern
    }
}

fn skip_value(password: Option<&str>, value: &str) -> bool {
    password.map_or(false, |password| value == password) || SKIP_VALUES.contains(&value)
}

fn title_from_path(depth: usize, path: &Path) -> String {
    if depth > 2 {
        panic!("unhandled depth > 2")
    } else if depth > 1 {
        let domain = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|os| os.to_str())
            .map(|s| s.to_string())
            .unwrap();
        let user = path
            .file_stem()
            .and_then(|os| os.to_str())
            .map(|s| s.to_string())
            .unwrap();
        format!("{} ({})", domain, user)
    } else {
        path.file_stem()
            .and_then(|os| os.to_str())
            .map(|s| s.to_string())
            .unwrap()
    }
}

impl<'a> From<RawRecord<'a>> for Record {
    fn from(mut raw: RawRecord) -> Record {
        let title = raw
            .fields
            .get("title")
            .map(|s| s.to_string())
            .unwrap_or_else(|| title_from_path(raw.depth, raw.path));
        if let Some(password) = raw.password {
            if raw.fields.contains_key("cardholder") && raw.fields.contains_key("number") {
                let card = read_credit_card(title, &raw);
                Record::CreditCard(card)
            } else {
                // Try to find username
                let username = raw
                    .fields
                    .iter()
                    .find_map(|(key, value)| {
                        for &field in LOGIN_FIELDS.iter() {
                            if matches(field, key) {
                                if field == "*mail" || field == "e" {
                                    // Ensure @ is present if we're matching on an email field
                                    if value.contains('@') {
                                        return Some(value.to_string());
                                    }
                                } else {
                                    return Some(value.to_string());
                                }
                            }
                        }
                        None
                    })
                    .or_else(|| {
                        // Nested item
                        if raw.depth > 1 {
                            raw.path
                                .file_stem()
                                .and_then(|os| os.to_str())
                                .map(|s| s.to_string())
                        } else {
                            None
                        }
                    });
                let website = WEBSITE_FIELDS
                    .iter()
                    .find_map(|&key| raw.fields.get(key).map(|&v| v))
                    .or_else(|| {
                        if raw.depth > 1 {
                            raw.path
                                .parent()
                                .and_then(|p| p.file_name())
                                .and_then(|os| os.to_str())
                        } else {
                            None
                        }
                    })
                    .map(|s| parse_url(s));

                // Remove fields that we don't need to retain now
                raw.fields.retain(|key, _value| {
                    !(WEBSITE_FIELDS.contains(&key.as_ref())
                        || LOGIN_FIELDS.iter().any(|&field| matches(field, key)))
                });
                let login = Login::new(
                    title,
                    website,
                    username,
                    Some(password.to_string()),
                    fields_to_notes(Some(password), raw.fields),
                );
                Record::Login(login)
            }
        } else if raw.fields.contains_key("license key") || raw.fields.contains_key("licensed to") {
            let version = raw
                .fields
                .get("product version")
                .or_else(|| raw.fields.get("version"))
                .map(|&s| String::from(s));
            let license_key = raw
                .fields
                .get("license key")
                .or_else(|| raw.fields.get("reg code"))
                .map(|&s| String::from(s));
            let your_name = raw
                .fields
                .get("licensed to")
                .or_else(|| raw.fields.get("reg name"))
                .map(|&s| String::from(s));
            let your_email = raw
                .fields
                .get("registered email")
                .or_else(|| raw.fields.get("reg email"))
                .map(|&s| String::from(s));
            // let company = raw.fields.get("")
            let download_link = raw
                .fields
                .get("download link")
                .or_else(|| raw.fields.get("download page"))
                .map(|link| link.parse().unwrap());
            let software_publisher = raw
                .fields
                .get("publisher name")
                .or_else(|| raw.fields.get("publisher"))
                .map(|&s| String::from(s));
            let publishers_website = raw
                .fields
                .get("publisher website")
                .or_else(|| raw.fields.get("website"))
                .map(|link| link.parse().unwrap());
            // let retail_price = raw.fields.get("");
            let support_email = raw.fields.get("support email").map(|&s| String::from(s));
            let purchase_date = raw.fields.get("order date").map(|&s| String::from(s));
            let order_number = raw.fields.get("order number").map(|&s| String::from(s));

            let software = SoftwareLicence {
                title,
                version,
                license_key,
                your_name,
                your_email,
                company: None,
                download_link,
                software_publisher,
                publishers_website,
                retail_price: None,
                support_email,
                purchase_date,
                order_number,
                notes: None,
            }
            .sanitise();
            Record::SoftwareLicence(software)
        } else if raw.fields.contains_key("number") {
            let card = read_credit_card(title, &raw);
            Record::CreditCard(card)
        } else {
            if let Some(notes) = NOTE_FIELDS.iter().find_map(|&key| raw.fields.get(key)) {
                let note = SecureNote {
                    title,
                    text: notes.to_string(),
                };
                Record::SecureNote(note)
            } else if raw.fields.contains_key("website") {
                let login = Login::new(
                    title,
                    Some(parse_url(raw.fields["website"])),
                    None,
                    None,
                    fields_to_notes(None, raw.fields),
                );
                Record::Login(login)
            } else {
                panic!("Unhandled item")
            }
        }
    }
}

fn fields_to_notes<'a>(
    password: Option<&str>,
    fields: LinkedHashMap<Cow<'a, str>, &'a str>,
) -> Option<String> {
    let notes = fields
        .into_iter()
        .filter_map(|(key, value)| {
            if skip_key(&key) || skip_value(password, value) {
                // eprintln!("skip: {} → {}", key, value);
                None
            } else {
                Some(format!("{}: {}", key, value))
            }
        })
        .collect::<Vec<_>>(); // TODO: use intersperse if/when stable https://github.com/rust-lang/rust/issues/79524
    if notes.is_empty() {
        None
    } else {
        Some(notes.join("\n"))
    }
}

fn parse_url(s: &str) -> Url {
    match s.parse() {
        Ok(url) => url,
        Err(ParseError::RelativeUrlWithoutBase) => {
            let fallback = String::from("https://") + s;
            fallback
                .parse()
                .expect(&format!("invalid fallback url: {}", fallback))
        }
        Err(e) => panic!("invalid url: {}", e),
    }
}

fn read_credit_card(title: String, raw: &RawRecord) -> CreditCard {
    let card_number = raw.fields.get("number").map(|&s| String::from(s));
    let expiry_date = raw
        .fields
        .get("expiry date")
        .or(raw.fields.get("expiry"))
        .map(|&s| String::from(s));
    let cardholder_name = raw.fields.get("cardholder").map(|&s| String::from(s));
    let pin = raw
        .password
        .or_else(|| raw.fields.get("pin").map(|&v| v))
        .map(String::from);
    let bank_name = raw.fields.get("bank name").map(|&s| String::from(s));
    let cvv = raw
        .fields
        .get("cvc")
        .or(raw.fields.get("cvv"))
        .map(|&s| String::from(s));
    let notes = None;

    let card = CreditCard {
        title,
        card_number: card_number.expect("missing card number"),
        expiry_date,
        cardholder_name,
        pin,
        bank_name,
        cvv,
        notes,
    };
    card
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::{CreditCard, Login, Record, SecureNote, SoftwareLicence};

    fn parse_path<P: AsRef<Path>>(path: P) -> Record {
        let path = path.as_ref();
        let content = fs::read_to_string(&path).unwrap();
        let depth = path.components().count() - 1;
        let raw = super::raw(&path, depth, &content);
        Record::from(raw)
    }

    #[test]
    fn test_myer() {
        // Tests:
        // * title has domain removed from file stem
        // * email field is only selected if it contains an @ in the value
        let actual = parse_path("tests/m.myer.com.au Myer.txt");
        let notes = r#"firstname: Wesley
lastname: Wesley
country: AU
address1: Level 1, 123 Example St
city: FITZROY
zipcode: 3065
state: VIC
phone1type: CEL
phone1: 0412345678"#;
        let expected = Record::Login(Login {
            title: String::from("Myer"),
            website: Some("https://m.myer.com.au/webapp/wcs/stores/servlet/m20OrderShippingBillingDetailsView?catalogId=10051&langId=-1&storeId=10251".parse().unwrap()),
            username: Some(String::from("test@example.com")),
            password: Some(String::from("this-is-a-test-password")),
            notes: Some(String::from(notes))
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_url_without_scheme() {
        let actual = parse_path("tests/bugzilla.mozilla.org Mozilla bugzilla.txt");
        let expected = Record::Login(Login {
            title: String::from("Mozilla bugzilla"),
            website: Some("https://bugzilla.mozilla.org/token.cgi".parse().unwrap()),
            username: Some(String::from("test@example.com")),
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_multiline_secure_note() {
        let actual = parse_path("tests/multiline secure note.txt");
        let text = r"# START OF EXAMPLE KEY FILE
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
DDDDDDDDDDDDDDDDDDDDDDDDDDD/DDDDDDDDD/DDDDDDDDDDDD+XtKG=
# END OF EXAMPLE KEY FILE
";
        let expected = Record::SecureNote(SecureNote {
            title: String::from("multiline secure note"),
            text: String::from(text),
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_multiline_secure_note_with_colons() {
        let actual = parse_path("tests/multiline secure note with colons.txt");
        let text = r"asfd

blargh: thing
";
        let expected = Record::SecureNote(SecureNote {
            title: String::from("multiline secure note with colons"),
            text: String::from(text),
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_multiline_secure_note_with_password() {
        let actual = parse_path("tests/multiline secure note with password.txt");
        let notes = Some(
            r"comments: line 1
line 2
line 3
"
            .to_string(),
        );
        let expected = Record::Login(Login {
            title: String::from("multiline secure note with password"),
            website: None,
            username: None,
            password: Some(String::from("this-is-a-test-password")),
            notes,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_just_password() {
        let actual = parse_path("tests/example.com.txt");
        let expected = Record::Login(Login {
            title: String::from("example.com"),
            website: Some("https://example.com".parse().unwrap()),
            username: None,
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_strip_generated_password() {
        let actual = parse_path("tests/Generated Password for example.com.txt");
        let expected = Record::Login(Login {
            title: String::from("example.com"),
            website: Some("http://example.com".parse().unwrap()),
            username: None,
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_keep_domain_in_title_when_ip_address() {
        let actual = parse_path("tests/192.168.0.8 (Administrator).txt");
        let expected = Record::Login(Login {
            title: String::from("192.168.0.8 (Administrator)"),
            website: Some("http://192.168.0.8".parse().unwrap()),
            username: Some(String::from("Administrator")),
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_keep_domain_in_title_when_second_part_is_username() {
        let actual = parse_path("tests/yousendit.com (test@example.com).txt");
        let expected = Record::Login(Login {
            title: String::from("yousendit.com (test@example.com)"),
            website: Some("http://yousendit.com".parse().unwrap()),
            username: Some(String::from("test@example.com")),
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_keep_domain_in_title_when_paren() {
        let actual = parse_path("tests/typekit.com (example).txt");
        let expected = Record::Login(Login {
            title: String::from("typekit.com (example)"),
            website: Some("https://typekit.com/users/new/trial".parse().unwrap()),
            username: Some(String::from("typekit@example.com")),
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_case_insensitive_pass() {
        let actual = parse_path("tests/wiki.trikeapps.com.txt");
        let expected = Record::Login(Login {
            title: String::from("wiki.trikeapps.com"),
            website: Some(
                "https://wiki.trikeapps.com/index.php/Special:UserLogin"
                    .parse()
                    .unwrap(),
            ),
            username: Some(String::from("Wmoore")),
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_strip_password_confirmations() {
        let actual = parse_path("tests/password confirmation.txt");
        let expected = Record::Login(Login {
            title: String::from("password confirmation"),
            website: Some("https://example.com".parse().unwrap()),
            username: Some(String::from("test@example.com")),
            password: Some(String::from("XXXXXXXXXXXXXXXXXXXX")),
            notes: Some(String::from("firstname: Wesley Moore")),
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_nested_login() {
        // Tests that the username, title, and url are picked from the path
        let actual = parse_path("tests/example.com/wezm.txt");
        let expected = Record::Login(Login {
            title: String::from("example.com (wezm)"),
            website: Some("https://example.com".parse().unwrap()),
            username: Some(String::from("wezm")),
            password: Some(String::from("this-is-a-test-password")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_software_license_incomplete() {
        let actual = parse_path("tests/Divvy.txt");
        let expected = Record::SoftwareLicence(SoftwareLicence {
            title: String::from("Divvy"),
            version: None,
            license_key: Some(String::from(
                "TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-AAAA",
            )),
            your_name: Some(String::from("Wesley Moore")),
            your_email: Some(String::from("test@example.com")),
            company: None,
            download_link: Some(
                "http://mizage.com/divvy/downloads/Divvy.zip"
                    .parse()
                    .unwrap(),
            ),
            software_publisher: None,
            publishers_website: None,
            retail_price: None,
            support_email: None,
            purchase_date: None,
            order_number: None,
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_software_license_complete() {
        let actual = parse_path("tests/agilebits.com 1Password 5.txt");
        let expected = Record::SoftwareLicence(SoftwareLicence {
            title: String::from("1Password 5"),
            version: Some(String::from("5.0.2")),
            license_key: None,
            your_name: Some(String::from("Wesley Moore")),
            your_email: Some(String::from("test@example.com")),
            company: None,
            download_link: Some("https://agilebits.com/downloads".parse().unwrap()),
            software_publisher: Some(String::from("AgileBits Inc.")),
            publishers_website: Some("https://agilebits.com/onepassword".parse().unwrap()),
            retail_price: None,
            support_email: Some(String::from("support@agilebits.com")),
            purchase_date: Some(String::from("6/10/2013")),
            order_number: Some(String::from("0000000")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_credit_card_1() {
        let actual = parse_path("tests/CC 1.txt");
        let expected = Record::CreditCard(CreditCard {
            title: String::from("CC 1"),
            card_number: String::from("376000000000000"),
            expiry_date: Some(String::from("02/20")),
            cardholder_name: Some(String::from("First Last")),
            pin: None,
            bank_name: None,
            cvv: Some(String::from("1234")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_credit_card_2() {
        let actual = parse_path("tests/CC 2.txt");
        let expected = Record::CreditCard(CreditCard {
            title: String::from("CC 2"),
            card_number: String::from("4100000000000000"),
            expiry_date: Some(String::from("02/2026")),
            cardholder_name: Some(String::from("First Last")),
            pin: Some(String::from("1234")),
            bank_name: None,
            cvv: Some(String::from("123")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }

    #[test]
    fn test_credit_card_3() {
        let actual = parse_path("tests/CC 3.txt");
        let expected = Record::CreditCard(CreditCard {
            title: String::from("CC 3"),
            card_number: String::from("370000000000000"),
            expiry_date: Some(String::from("0/6/2018")),
            cardholder_name: None,
            pin: Some(String::from("4567")),
            bank_name: None,
            cvv: Some(String::from("1234")),
            notes: None,
        });
        assert_eq!(actual, expected)
    }
}
