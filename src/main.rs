mod parse;

use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, io};

use serde::Serialize;
use url::Url;
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
    website: Option<Url>,
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
    download_link: Option<Url>,
    software_publisher: Option<String>,
    publishers_website: Option<Url>,
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
        website: Some("https://example.com".parse().unwrap()),
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
        .skip(20)
        .take(10)
    {
        let entry = entry.unwrap();
        println!("{}", entry.path().display());
        if entry.file_type().is_file() {
            let path = entry.path();
            let contents = decrypt(path)?;
            let raw = parse::raw(path, &contents);
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

fn usage() {
    eprintln!("Usage: pass2csv path/to/password/store");
    std::process::exit(1);
}

impl Login {
    fn new(
        mut title: String,
        website: Option<Url>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
    ) -> Self {
        if let (true, Some(url)) = (title.contains(' '), &website) {
            let (first, rest) = title.split_once(' ').unwrap();
            if url.host_str() == Some(first) {
                // Strip the leading domain name from the title
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
