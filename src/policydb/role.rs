use croaring::Bitmap;
use policydb::ty::TypeSet;
use policydb::CompatibilityProfile;
use policydb::Feature;
use policydb::PolicyObject;
use policydb::PolicyReadError;
use policydb::PolicyReader;
use policydb::PolicyType;
use policydb::Symbol;
use std::io::Read;

#[derive(Debug)]
pub struct Role {
    id: u32,
    name: String,
    dominates: Bitmap,
    type_set: TypeSet,
    flavor: Option<u32>,
    roles: Option<Bitmap>,
}

#[derive(Debug)]
pub enum RoleSet {
    Bitmap(Bitmap),
    Set { roles: Bitmap, flags: u32 },
}

impl PolicyObject for RoleSet {
    fn decode<R: Read>(reader: &mut PolicyReader<R>) -> Result<Self, PolicyReadError> {
        let profile = reader.profile();

        if profile.ty().is_kernel_policy() {
            Ok(RoleSet::Bitmap(reader.read_object()?))
        } else {
            let roles: Bitmap = reader.read_object()?;
            let flags = reader.read_u32()?;

            Ok(RoleSet::Set { roles, flags })
        }
    }
}

impl Symbol for Role {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for Role {
    fn decode<R: Read>(reader: &mut PolicyReader<R>) -> Result<Self, PolicyReadError> {
        let name_len = reader.read_u32()? as usize;
        let id = reader.read_u32()?;

        let bounds = if reader.profile().supports(Feature::Boundary) {
            Some(reader.read_u32()?)
        } else {
            None
        };

        let name = reader.read_string(name_len)?;
        let dominates = reader.read_object()?;

        let is_kernel_policy = reader.profile().ty().is_kernel_policy();
        let (type_set, flavor, roles) = if is_kernel_policy {
            (TypeSet::Bitmap(reader.read_object()?), None, None)
        } else {
            (
                reader.read_object()?,
                Some(reader.read_u32()?),
                Some(reader.read_object()?),
            )
        };

        Ok(Role {
            id,
            name,
            dominates,
            type_set,
            flavor,
            roles,
        })
    }
}
