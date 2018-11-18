use policydb::mls::MlsLevel;
use policydb::mls::MlsRange;
use policydb::profile::CompatibilityProfile;
use policydb::profile::Feature;
use policydb::reader::ReadError;
use policydb::role::RoleSet;
use policydb::symtable::Symbol;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;

pub struct User {
    id: u32,
    name: String,
}

impl Symbol for User {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for User {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()? as usize;
        let id = reader.read_u32()?;
        let bounds = if reader.profile().supports(Feature::Boundary) {
            Some(reader.read_u32()?)
        } else {
            None
        };

        let name = reader.read_string(name_len)?;
        let role_set: RoleSet = reader.read_object()?;

        let is_mls_supported = reader.profile().supports(Feature::Mls);
        let is_mls_users_supported = reader.profile().supports(Feature::MlsUsers);

        unimplemented!()
    }
}
