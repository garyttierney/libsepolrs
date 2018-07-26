use policydb::reader::ReadError;
use policydb::symtable::Symbol;
use policydb::symtable::SymbolTable;
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

    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()?;
        let id = reader.read_u32()?;
        let num_perm_names = reader.read_u32()?;
        let num_perm_elements = reader.read_u32()?;
        let name = reader.read_string(name_len as usize)?;
        let permissions = reader.read_bare_symbol_table::<Permission>(num_perm_elements as usize)?;

        Ok(Common {
            id,
            name,
            permissions,
        })
    }
}

#[derive(Debug)]
pub struct Permission {
    id: u32,
    name: String,
}

impl Symbol for Permission {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()?;
        let id = reader.read_u32()?;
        let name = reader.read_string(name_len as usize)?;

        Ok(Permission { id, name })
    }
}
