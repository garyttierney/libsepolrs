use croaring::Bitmap;
use policydb::profile::CompatibilityProfile;
use policydb::reader::ReadError;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;

pub struct MlsLevel {
    sensitivity: u32,
    categories: Bitmap,
}

pub struct MlsSemanticLevel {}

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
