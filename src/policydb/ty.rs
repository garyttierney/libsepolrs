use croaring::Bitmap;
use policydb::profile::CompatibilityProfile;
use policydb::profile::Feature;
use policydb::reader::ReadError;
use policydb::symtable::Symbol;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;

bitflags! {
    struct TyProperties: u32 {
        const Primary = 0x0001;
        const Attribute	= 0x0002;
        const Alias	= 0x0004;/* userspace only */
        const Permissive = 0x0008	;/* userspace only */
    }
}

bitflags! {
    struct TyFlags: u32 {
        const Permissive = 0x0001;
    }
}

#[derive(Debug)]
pub enum TypeSet {
    Bitmap(Bitmap),
    Set {
        types: Bitmap,
        inverse_types: Bitmap,
        flags: u32,
    },
}

#[derive(Debug)]
pub struct Type {
    id: u32,
    name: String,
    primary: bool,
    flavor: Option<u32>,
    flags: TyFlags,
    bounds: Option<u32>,
    assoc_types: Option<Bitmap>,
}

impl Symbol for Type {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for Type {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let is_kern_policy = reader.profile().ty().is_kernel_policy();

        let name_len = reader.read_u32()? as usize;
        let id = reader.read_u32()?;

        let (primary, flavor, flags, bounds) = if reader.profile().supports(Feature::Boundary) {
            let mut primary = if reader.profile().supports(Feature::BoundaryAlias) {
                reader.read_u32()? == 1
            } else {
                false
            };

            let flags = TyFlags::empty();
            let properties = TyProperties::from_bits(reader.read_u32()?)
                .ok_or(ReadError::InvalidPolicyCapability)?;

            let permissive = properties.contains(TyProperties::Permissive);
            let flavor = if properties.contains(TyProperties::Attribute) {
                Some(1) // todo: fix
            } else if properties.contains(TyProperties::Alias) {
                Some(2) // todo: fix
            } else {
                None
            };

            if properties.contains(TyProperties::Primary) {
                primary = true;
            };

            let bounds = reader.read_u32()?;

            (primary, flavor, flags, Some(bounds))
        } else {
            let primary = reader.read_u32()? == 1;
            let flavor = if !is_kern_policy {
                Some(reader.read_u32()?)
            } else {
                None
            };

            let flags = if is_kern_policy {
                TyFlags::from_bits(reader.read_u32()?).ok_or(ReadError::InvalidPolicyCapability)?
            } else {
                TyFlags::empty()
            };

            (primary, flavor, flags, None)
        };

        let assoc_types = if !is_kern_policy {
            Some(reader.read_object()?)
        } else {
            None
        };

        let name = reader.read_string(name_len)?;

        Ok(Type {
            id,
            name,
            primary,
            flavor,
            flags,
            bounds,
            assoc_types,
        })
    }
}

impl PolicyObject for TypeSet {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let profile = reader.profile();

        if profile.ty().is_kernel_policy() {
            Ok(TypeSet::Bitmap(reader.read_object()?))
        } else {
            let types: Bitmap = reader.read_object()?;
            let inverse_types: Bitmap = reader.read_object()?;
            let flags = reader.read_u32()?;

            Ok(TypeSet::Set {
                types,
                inverse_types,
                flags,
            })
        }
    }
}
