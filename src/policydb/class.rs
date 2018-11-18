use policydb::cons::Constraint;
use policydb::profile::CompatibilityProfile;
use policydb::profile::Feature;
use policydb::reader::ReadError;
use policydb::symtable::Symbol;
use policydb::symtable::SymbolTable;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;

#[derive(Debug)]
pub struct Common {
    id: u32,
    name: String,
    permissions: SymbolTable<Permission>,
}

impl Common {
    pub fn permissions(&self) -> &SymbolTable<Permission> {
        &self.permissions
    }
}

impl Symbol for Common {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for Common {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()?;
        let id = reader.read_u32()?;
        let num_perm_names = reader.read_u32()?;
        let num_perm_elements = reader.read_u32()?;
        let name = reader.read_string(name_len as usize)?;
        let permissions =
            reader.read_bare_symbol_table::<Permission>(num_perm_elements as usize)?;

        Ok(Common {
            id,
            name,
            permissions,
        })
    }
}

#[derive(Debug)]
pub struct Class {
    id: u32,
    name: String,
    common_name: Option<String>,
    permissions: SymbolTable<Permission>,
    constraints: Vec<Constraint>,
    transition_constraints: Vec<Constraint>,
    default_user: Option<u32>,
    default_role: Option<u32>,
    default_range: Option<u32>,
    default_type: Option<u32>,
}

impl Symbol for Class {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        &self.name.as_str()
    }
}

impl PolicyObject for Class {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()?;
        let common_name_len = reader.read_u32()?;
        let id = reader.read_u32()?;
        let _num_perm_names = reader.read_u32()?;
        let num_perm_elements = reader.read_u32()? as usize;
        let num_constraints = reader.read_u32()? as usize;

        let name = reader.read_string(name_len as usize)?;
        let common_name = if common_name_len == 0 {
            None
        } else {
            Some(reader.read_string(common_name_len as usize)?)
        };

        let permissions: SymbolTable<Permission> =
            reader.read_bare_symbol_table(num_perm_elements as usize)?;

        let constraints: Vec<Constraint> = reader.read_objects(num_constraints)?;
        let transition_constraints = if reader.profile().supports(Feature::ValidateTransition) {
            let num_transition_constraints = reader.read_u32()? as usize;
            reader.read_objects::<Constraint>(num_transition_constraints)?
        } else {
            vec![]
        };

        let (default_user, default_range, default_role) =
            if reader.profile().supports(Feature::NewObjectDefaults) {
                (
                    Some(reader.read_u32()?),
                    Some(reader.read_u32()?),
                    Some(reader.read_u32()?),
                )
            } else {
                (None, None, None)
            };

        let default_type = if reader.profile().supports(Feature::DefaultType) {
            Some(reader.read_u32()?)
        } else {
            None
        };

        Ok(Class {
            id,
            name,
            common_name,
            permissions,
            constraints,
            transition_constraints,
            default_user,
            default_range,
            default_role,
            default_type,
        })
    }
}

#[derive(Debug)]
pub struct Permission {
    id: u32,
    name: String,
}

impl PolicyObject for Permission {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()?;
        let id = reader.read_u32()?;
        let name = reader.read_string(name_len as usize)?;

        Ok(Permission { id, name })
    }
}

impl Symbol for Permission {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}
