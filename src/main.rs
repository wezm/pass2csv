use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::fs::FileType;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, io};

use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Serialize)]
enum Record {
    Login(Login),
    CreditCard(CreditCard),
    SoftwareLicence(SoftwareLicence),
    SecureNote(SecureNote),
}

#[derive(Debug)]
struct RawRecord<'a> {
    path: &'a Path,
    password: Option<&'a str>,
    fields: HashMap<Cow<'a, str>, &'a str>,
}

#[derive(Debug, Serialize)]
struct Login {
    title: String,
    website: Option<String>,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreditCard {
    title: String,
    card_number: String,
    expiry_date: Option<String>, // (MM/YYYY)
    cardholder_name: Option<String>,
    pin: Option<String>,
    bank_name: Option<String>,
    cvv: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct SoftwareLicence {
    title: String,
    version: Option<String>,
    license_key: Option<String>,
    your_name: Option<String>,
    your_email: Option<String>,
    company: Option<String>,
    download_link: Option<String>,
    software_publisher: Option<String>,
    publishers_website: Option<String>,
    retail_price: Option<String>,
    support_email: Option<String>,
    purchase_date: Option<String>,
    order_number: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct SecureNote {
    title: String,
    text: String,
}

fn example() -> Result<(), Box<dyn Error>> {
    let mut csv = csv::Writer::from_writer(io::stdout());
    let rec = Login {
        title: String::from("Title"),
        website: Some(String::from("https://example.com")),
        username: Some(String::from("wezm")),
        password: Some(String::from("hunter2")),
        notes: None,
    };

    csv.serialize(&rec)?;
    Ok(())
}

fn main() {
    let path = env::args_os().skip(1).next();
    if path.is_none() {
        usage();
    }
    let path = PathBuf::from(path.unwrap());

    if let Err(err) = walk(&path) {
        println!("Error: {}", err);
    }
    example().unwrap();
}

fn gpg_file_or_dir(entry: &DirEntry) -> bool {
    entry.file_type().is_dir() || gpg_file(entry)
}

fn gpg_file(entry: &DirEntry) -> bool {
    entry.path().extension().map_or(false, |ext| ext == "gpg")
}

fn not_hidden(entry: &DirEntry) -> bool {
    entry.depth() == 0
        || !entry
            .file_name()
            .to_str()
            .map_or(false, |s| s.starts_with("."))
}

fn entry_filter(entry: &DirEntry) -> bool {
    not_hidden(entry) && gpg_file_or_dir(entry)
}

fn walk(path: &Path) -> Result<(), Box<dyn Error>> {
    let walker = WalkDir::new(path).follow_links(true).into_iter();
    for entry in walker
        .filter_entry(entry_filter)
        .into_iter()
        .skip(0)
        .take(10)
    {
        let entry = entry.unwrap();
        println!("{}", entry.path().display());
        if entry.file_type().is_file() {
            let path = entry.path();
            let contents = decrypt(path)?;
            let raw = parse_raw(path, &contents);
            println!("{:#?}", raw);
            let rec = Record::from(raw);
            println!("{:#?}", rec);
        }
    }
    Ok(())
}

fn decrypt(path: &Path) -> Result<String, Box<dyn Error>> {
    let output = Command::new("gpg")
        .args(&["--decrypt", "--quiet", "--use-agent"])
        .arg(path)
        .stderr(Stdio::inherit())
        .output()?;
    if output.status.success() {
        let s = String::from_utf8(output.stdout)?;
        Ok(s)
    } else {
        Err(String::from("gpg command did not run successfully").into())
    }
}

const SKIP_KEYS: &[&str] = &["^html", "^recaptcha", "commit", "op"];
const SKIP_VALUES: &[&str] = &["✓"];

fn parse_raw<'a>(path: &'a Path, item: &'a str) -> RawRecord<'a> {
    if item.lines().count() == 1
        && item
            .lines()
            .next()
            .map_or(false, |line| !line.contains(": "))
    {
        return RawRecord {
            path,
            password: Some(item.trim_end()),
            fields: HashMap::new(),
        };
    }

    if item.split(':').count() == 2 {
        let (key, value) = item.split_once(':').unwrap();
        if !key.contains('\n') {
            let mut fields = HashMap::new();
            fields.insert(Cow::from(key), value.trim_start());
            return RawRecord {
                path,
                password: None,
                fields,
            };
        }
    }

    let mut lines = item.lines();
    let mut fields = HashMap::new();
    let mut password = None;

    for line in lines {
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

const LOGIN_FIELDS: &[&str] = &[
    "login",
    "username",
    "mail",
    "membership no",
    "medicarecardnumber",
];
const NOTE_FIELDS: &[&str] = &["comments"];
const WEBSITE_FIELDS: &[&str] = &["location", "url", "website"];

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
                        return Some(value.to_string());
                    }
                }
                None
            });
            let website = WEBSITE_FIELDS
                .iter()
                .find_map(|&key| raw.fields.get(key))
                .map(|s| s.to_string());
            // Remove fields that we don't need to retain now
            raw.fields.retain(|key, _value| {
                !(WEBSITE_FIELDS.contains(&key.as_ref())
                    || LOGIN_FIELDS.iter().any(|&field| key.contains(field)))
            });
            let login = Login {
                title,
                website,
                username,
                password: Some(password.to_string()),
                notes: fields_to_notes(raw.fields),
            };
            Record::Login(login)
        } else {
            if let Some(notes) = NOTE_FIELDS.iter().find_map(|&key| raw.fields.get(key)) {
                let note = SecureNote {
                    title,
                    text: notes.to_string(),
                };
                Record::SecureNote(note)
            } else if raw.fields.contains_key("website") {
                let login = Login {
                    title,
                    website: Some(raw.fields["website"].to_string()),
                    username: None,
                    password: None,
                    notes: fields_to_notes(raw.fields),
                };
                Record::Login(login)
            } else {
                panic!("Unhandled item")
            }
        }
    }
}

fn fields_to_notes<'a>(fields: HashMap<Cow<'a, str>, &'a str>) -> Option<String> {
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

fn usage() {
    eprintln!("Usage: pass2csv path/to/password/store");
    std::process::exit(1);
}
