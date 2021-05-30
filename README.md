pass2csv
========

Tool to export data from [pass] for import into another password manager.

Disclaimers
-----------

* I wrote this to serve my own need to import more than 1500 items from `pass`
  into [1Password] for Linux. The data in `pass` had passed through several
  password managers already and was a bit messy. `pass2csv` tries to clean up
  the data as it goes but a lot of this is likely unique to my data.
* This code is not the finest Rust code I've ever written. It leans more towards
  just getting the job done than usual. Having said that it's not completely 
  terrible and there is a small set of tests.

Usage
-----

After building (`cargo build --release`):

    ./target/release/pass2csv path/to/your/password/store

The tool will produce four CSV files:

* `credit_cards.csv`
* `logins.csv`
* `notes.csv`
* `software.csv`

Licence
-------

This project is dual licenced under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/wezm/frond/blob/master/LICENSE-APACHE))
- MIT license ([LICENSE-MIT](https://github.com/wezm/frond/blob/master/LICENSE-MIT))

at your option.

[pass]: https://www.passwordstore.org/
[1Password]: https://1password.com/
