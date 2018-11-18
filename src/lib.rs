#![feature(nll)]

extern crate byteorder;
extern crate croaring;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate bitflags;

use policydb::reader::ReadError;
use policydb::Policy;

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub mod policydb;

pub fn load_policy_from_file<P: AsRef<Path>>(path: P) -> Result<Policy, ReadError> {
    let file = File::open(path).unwrap();
    let file_reader = BufReader::new(file);
    let mut policy_reader = policydb::Reader::new(file_reader);

    policy_reader.read_policy()
}
