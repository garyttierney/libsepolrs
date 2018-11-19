use croaring::Bitmap;
use policydb::profile::CompatibilityProfile;
use policydb::reader::ReadError;
use policydb::symtable::Symbol;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;

#[derive(Debug)]
pub struct MlsLevel {
    sensitivity: u32,
    categories: Bitmap,
}

impl PolicyObject for MlsLevel {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let sensitivity = reader.read_u32()?;
        let categories = reader.read_object()?;

        Ok(MlsLevel {
            sensitivity,
            categories,
        })
    }
}

impl MlsLevel {
    pub fn decode_expanded<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let sensitivity = reader.read_u32()?;
        let num_cats = reader.read_u32()?;
        let mut categories = Bitmap::create();

        for _ in 0..num_cats {
            let low = reader.read_u32()?;
            let high = reader.read_u32()?;

            categories.add_range_closed((low..high))
        }

        Ok(MlsLevel {
            sensitivity,
            categories,
        })
    }
}

#[derive(Debug)]
pub struct MlsRange {
    low: MlsLevel,
    high: MlsLevel,
}

impl PolicyObject for MlsRange {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let items = reader.read_u32()?;
        let s1 = reader.read_u32()?;
        let s2 = if items > 1 { reader.read_u32()? } else { s1 };

        let s1_cats: Bitmap = reader.read_object()?;
        let s2_cats = if items > 1 {
            reader.read_object()?
        } else {
            s1_cats.clone()
        };

        Ok(MlsRange {
            low: MlsLevel {
                sensitivity: s1,
                categories: s1_cats,
            },
            high: MlsLevel {
                sensitivity: s2,
                categories: s2_cats,
            },
        })
    }
}

impl MlsRange {
    pub fn decode_expanded<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let low = MlsLevel::decode_expanded(reader)?;
        let high = MlsLevel::decode_expanded(reader)?;

        Ok(MlsRange { low, high })
    }
}

#[derive(Debug)]
pub struct Sensitivity {
    id: u32,
    name: String,
    level: MlsLevel,
    is_alias: bool,
}

impl Symbol for Sensitivity {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for Sensitivity {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()? as usize;
        let is_alias = reader.read_u32()? == 1;
        let name = reader.read_string(name_len)?;
        let level: MlsLevel = reader.read_object()?;

        Ok(Sensitivity {
            id: 0,
            name,
            level,
            is_alias,
        })
    }
}

#[derive(Debug)]
pub struct Category {
    id: u32,
    name: String,
    is_alias: bool,
}

impl Symbol for Category {
    fn id(&self) -> u32 {
        self.id
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PolicyObject for Category {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let name_len = reader.read_u32()? as usize;
        let id = reader.read_u32()?;
        let is_alias = reader.read_u32()? == 1;
        let name = reader.read_string(name_len)?;

        Ok(Category { id, name, is_alias })
    }
}
