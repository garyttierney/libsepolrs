use croaring::Bitmap;
use policydb::CompatibilityProfile;
use policydb::PolicyObject;
use policydb::PolicyReadError;
use policydb::PolicyReader;
use std::io::Read;

impl PolicyObject for Bitmap {
    fn decode<R: Read>(reader: &mut PolicyReader<R>) -> Result<Self, PolicyReadError> {
        let map_size = reader.read_u32()?;
        let high_bit = reader.read_u32()?;
        let map_count = reader.read_u32()?;
        let mut bitmap = Bitmap::create_with_capacity(map_count);

        for map_idx in 0..map_count {
            let start_bit = reader.read_u32()?;
            let map = reader.read_u64()?;

            for bit in 0..64 {
                if (1 << bit) & map != 0 {
                    bitmap.add(start_bit + bit as u32);
                }
            }
        }

        Ok(bitmap)
    }
}
