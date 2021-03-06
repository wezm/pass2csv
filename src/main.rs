mod parse;

use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use std::fs::File;
use std::io::Write;
use url::Url;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Serialize, Eq, PartialEq)]
enum Record {
    Login(Login),
    CreditCard(CreditCard),
    SoftwareLicence(SoftwareLicence),
    SecureNote(SecureNote),
}

#[derive(Debug, Serialize, Eq, PartialEq)]
struct Login {
    title: String,
    website: Option<Url>,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
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

#[derive(Debug, Serialize, Eq, PartialEq)]
struct SoftwareLicence {
    title: String,
    version: Option<String>,
    license_key: Option<String>,
    your_name: Option<String>,
    your_email: Option<String>,
    company: Option<String>,
    download_link: Option<Url>,
    software_publisher: Option<String>,
    publishers_website: Option<Url>,
    retail_price: Option<String>,
    support_email: Option<String>,
    purchase_date: Option<String>,
    order_number: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
struct SecureNote {
    title: String,
    text: String,
}

struct Writer<W: Write> {
    login: csv::Writer<W>,
    credit_card: csv::Writer<W>,
    software_licence: csv::Writer<W>,
    secure_note: csv::Writer<W>,
}

fn main() {
    let path = env::args_os().skip(1).next();
    if path.is_none() {
        usage();
    }
    let path = PathBuf::from(path.unwrap());

    if let Err(err) = main_loop(&path) {
        eprintln!("Error: {}", err);
    }
}

fn main_loop(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut writer = Writer::default();
    for record in walk(&path) {
        let record = record?;
        writer.write(&record)?;
    }

    Ok(())
}

fn gpg_file_or_dir(entry: &DirEntry) -> bool {
    entry.file_type().is_dir() || gpg_file(entry)
}

fn gpg_file(entry: &DirEntry) -> bool {
    entry.path().extension().map_or(false, |ext| ext == "gpg")
}

fn docker_credential_helper(entry: &DirEntry) -> bool {
    entry
        .path()
        .components()
        .find(|component| component.as_os_str() == "docker-credential-helpers")
        .is_some()
}

fn not_hidden(entry: &DirEntry) -> bool {
    entry.depth() == 0
        || !entry
            .file_name()
            .to_str()
            .map_or(false, |s| s.starts_with("."))
}

fn entry_filter(entry: &DirEntry) -> bool {
    not_hidden(entry) && gpg_file_or_dir(entry) && !docker_credential_helper(entry)
}

fn walk(path: &Path) -> impl Iterator<Item = Result<Record, Box<dyn Error>>> {
    let walker = WalkDir::new(path).follow_links(true).into_iter();
    walker
        .filter_entry(entry_filter)
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            eprintln!("{}", entry.path().display());
            if entry.file_type().is_file() {
                let path = entry.path();
                let res = decrypt(path).map(|contents| {
                    let raw = parse::raw(path, entry.depth(), &contents);
                    // println!("{:#?}", raw);
                    let rec = Record::from(raw);
                    // println!("{:#?}", rec);
                    rec
                });
                Some(res)
            } else {
                None
            }
        })
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

fn usage() {
    eprintln!("Usage: pass2csv path/to/password/store");
    std::process::exit(1);
}

impl Login {
    fn new(
        mut title: String,
        mut website: Option<Url>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
    ) -> Self {
        // If website is empty but title looks like it could work as a url, try that
        if website.is_none() && title.contains('.') && !title.contains(' ') {
            if let Ok(maybe_website) = format!("https://{}", title).parse() {
                website = Some(maybe_website);
            }
        }

        const GENERATED_FOR: &str = "Generated Password for ";
        if title.starts_with(GENERATED_FOR) {
            title.replace_range(..GENERATED_FOR.len(), "");
        }

        // Strip the leading domain name from the title if present
        let candidate = title.contains(' ') && !title.contains('(');
        if let (true, Some(host)) = (candidate, website.as_ref().and_then(|url| url.host_str())) {
            let (first, rest) = title.split_once(' ').unwrap();
            if host == first {
                title = rest.to_string()
            }
        }

        Login {
            title,
            website,
            username,
            password,
            notes,
        }
    }
}

impl SoftwareLicence {
    fn sanitise(mut self) -> Self {
        // Strip the leading domain name from the title if present
        let host = self
            .download_link
            .as_ref()
            .or(self.publishers_website.as_ref())
            .and_then(|url| url.host_str());
        let title = &self.title;
        let candidate = title.contains(' ') && !title.contains('(');
        if let (true, Some(host)) = (candidate, host) {
            let (first, rest) = title.split_once(' ').unwrap();
            if host == first {
                self.title = rest.to_string()
            }
        }
        self
    }
}

impl Default for Writer<File> {
    fn default() -> Self {
        Writer {
            login: csv::Writer::from_path("logins.csv").unwrap(),
            credit_card: csv::Writer::from_path("credit_cards.csv").unwrap(),
            software_licence: csv::Writer::from_path("software.csv").unwrap(),
            secure_note: csv::Writer::from_path("notes.csv").unwrap(),
        }
    }
}

impl<W: Write> Writer<W> {
    fn write(&mut self, record: &Record) -> csv::Result<()> {
        match record {
            Record::Login(login) => self.login.serialize(login),
            Record::CreditCard(card) => self.credit_card.serialize(card),
            Record::SoftwareLicence(licence) => self.software_licence.serialize(licence),
            Record::SecureNote(note) => self.secure_note.serialize(note),
        }
    }
}
