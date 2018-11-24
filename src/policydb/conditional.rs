use policydb::Feature;
use policydb::PolicyObject;
use policydb::PolicyReadError;
use policydb::PolicyReader;
use policydb::Symbol;
use std::io::Read;

#[derive(Debug)]
pub struct Boolean {
    id: u32,
    name: String,
    state: bool,
    flags: u32,
}

impl Boolean {
    pub fn is_toggled(&self) -> bool {
        self.state
    }
}

impl Symbol for Boolean {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for Boolean {
    fn decode<R: Read>(reader: &mut PolicyReader<R>) -> Result<Self, PolicyReadError> {
        let id = reader.read_u32()?;
        let state = reader.read_u32()? == 1;
        let name_len = reader.read_u32()? as usize;
        let name = reader.read_string(name_len)?;

        let flags = if reader.profile().supports(Feature::TunableSep) {
            reader.read_u32()?
        } else {
            0
        };

        Ok(Boolean {
            id,
            name,
            state,
            flags,
        })
    }
}
