use std::borrow::Cow;
use std::path::Path;

use hashlink::LinkedHashMap;
use url::{ParseError, Url};

use crate::{Login, RawRecord, Record, SecureNote, SoftwareLicence};

const SKIP_KEYS: &[&str] = &["^html", "^recaptcha", "commit", "op", "label"];
const SKIP_VALUES: &[&str] = &["✓"];
const LOGIN_FIELDS: &[&str] = &[
    "login",
    "username",
    "mail",
    "membership no",
    "medicarecardnumber",
];
const NOTE_FIELDS: &[&str] = &["comments"];
const WEBSITE_FIELDS: &[&str] = &["location", "url", "website"];

pub(crate) fn raw<'a>(path: &'a Path, item: &'a str) -> RawRecord<'a> {
    if item.lines().count() == 1
        && item
            .lines()
            .next()
            .map_or(false, |line| !line.contains(": "))
    {
        return RawRecord {
            path,
            password: Some(item.trim_end()),
            fields: LinkedHashMap::new(),
        };
    }

    if item.split(':').count() == 2 {
        let (key, value) = item.split_once(':').unwrap();
        if !key.contains('\n') {
            let mut fields = LinkedHashMap::new();
            fields.insert(Cow::from(key), value.trim_start());
            return RawRecord {
                path,
                password: None,
                fields,
            };
        }
    }

    let mut fields = LinkedHashMap::new();
    let mut password = None;

    for line in item.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            if key.contains("pass") {
                // Use as password or skip if password is already set
                if password.is_none() {
                    password = Some(value.trim_start())
                }
            } else if value == "✓" {
                // skip
            } else {
                fields.insert(Cow::from(key.to_ascii_lowercase()), value.trim_start());
            }
        } else if password.is_none() {
            password = Some(line)
        } else {
            panic!("error: malformed item: {}", item);
        }
    }

    RawRecord {
        path,
        password,
        fields,
    }
}

fn skip_key(key: &str) -> bool {
    key.is_empty()
        || SKIP_KEYS.iter().any(|&skip| {
            if skip.starts_with('^') {
                key.starts_with(&skip[1..])
            } else {
                key == skip
            }
        })
}

fn skip_value(value: &str) -> bool {
    SKIP_VALUES.contains(&value)
}

fn title_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|os| os.to_str())
        .map(|s| s.to_string())
        .unwrap()
}

impl<'a> From<RawRecord<'a>> for Record {
    fn from(mut raw: RawRecord) -> Record {
        let title = raw
            .fields
            .get("title")
            .map(|s| s.to_string())
            .unwrap_or_else(|| title_from_path(raw.path));
        if let Some(password) = raw.password {
            // Try to find username
            let username = raw.fields.iter().find_map(|(key, value)| {
                for &field in LOGIN_FIELDS.iter() {
                    if key.contains(field) {
                        if field == "mail" {
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
            });
            let website = WEBSITE_FIELDS
                .iter()
                .find_map(|&key| raw.fields.get(key))
                .map(|&s| parse_url(s));
            // Remove fields that we don't need to retain now
            raw.fields.retain(|key, _value| {
                !(WEBSITE_FIELDS.contains(&key.as_ref())
                    || LOGIN_FIELDS.iter().any(|&field| key.contains(field)))
            });
            let login = Login::new(
                title,
                website,
                username,
                Some(password.to_string()),
                fields_to_notes(raw.fields),
            );
            Record::Login(login)
        } else if raw.fields.contains_key("licensed to") {
            // FIXME
            let software = SoftwareLicence {
                title,
                version: None,
                license_key: None,
                your_name: None,
                your_email: None,
                company: None,
                download_link: None,
                software_publisher: None,
                publishers_website: None,
                retail_price: None,
                support_email: None,
                purchase_date: None,
                order_number: None,
                notes: None,
            };
            Record::SoftwareLicence(software)
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
                    fields_to_notes(raw.fields),
                );
                Record::Login(login)
            } else {
                panic!("Unhandled item")
            }
        }
    }
}

fn fields_to_notes<'a>(fields: LinkedHashMap<Cow<'a, str>, &'a str>) -> Option<String> {
    let notes = fields
        .into_iter()
        .filter_map(|(key, value)| {
            if skip_key(&key) || skip_value(value) {
                eprintln!("skip: {} → {}", key, value);
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
            (String::from("https://") + s).parse().expect("invalid url")
        }
        Err(e) => panic!("invalid url: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::{Login, Record, SecureNote};

    fn parse_path<P: AsRef<Path>>(path: P) -> Record {
        let path = path.as_ref();
        let content = fs::read_to_string(&path).unwrap();
        let raw = super::raw(&path, &content);
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
phone1: 0412345678
create-account: Y"#;
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
}
