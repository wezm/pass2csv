use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::{env, io};

use serde::Serialize;
use std::fs::FileType;
use std::process::{Command, Stdio};
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Serialize)]
struct Login {
    title: Option<String>,
    website: Option<String>,
    username: Option<String>,
    password: String,
    notes: Option<String>,
    // custom_fields: HashMap<String, String>
}

fn example() -> Result<(), Box<dyn Error>> {
    let mut csv = csv::Writer::from_writer(io::stdout());
    let rec = Login {
        title: Some(String::from("Title")),
        website: Some(String::from("https://example.com")),
        username: Some(String::from("wezm")),
        password: String::from("hunter2"),
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
    for entry in walker.filter_entry(entry_filter).into_iter().take(10) {
        let entry = entry.unwrap();
        println!("{}", entry.path().display());
        if entry.file_type().is_file() {
            let contents = decrypt(entry.path())?;
            println!("{}", contents);
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
