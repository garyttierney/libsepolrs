use byteorder::{LittleEndian, ReadBytesExt};
use croaring::Bitmap;

use policydb::constants::*;
use policydb::feature::Feature;
use policydb::polcap::{PolicyCapability, PolicyCapabilitySet};
use policydb::profile::CompatibilityProfile;
use policydb::{Policy, PolicyTargetPlatform, PolicyType};

use std::error::Error;
use std::fmt;
use std::io::Error as IoError;
use std::io::Read;
use std::str;

/// Decodes the policy representation from a binary format.
pub struct Reader<R: Read> {
    buf: R,
}

#[derive(Debug)]
pub enum ReadError {
    InvalidMagicCode(u32),
    InvalidPolicyCapability,
    InvalidTargetPlatform(String),
    InvalidVersion(u32),
    InputError(IoError),
}

impl From<IoError> for ReadError {
    fn from(input_error: IoError) -> Self {
        ReadError::InputError(input_error)
    }
}

impl Error for ReadError {
    fn description(&self) -> &str {
        "Something bad happened"
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Oh no, something bad went down")
    }
}

impl<R: Read> Reader<R> {
    pub fn new(buf: R) -> Self {
        Reader { buf }
    }

    pub fn read_u32(&mut self) -> Result<u32, IoError> {
        self.buf.read_u32::<LittleEndian>()
    }

    pub fn read_u64(&mut self) -> Result<u64, IoError> {
        self.buf.read_u64::<LittleEndian>()
    }

    pub fn read_string(&mut self, len: usize) -> Result<String, IoError> {
        let mut value = String::with_capacity(len);
        let data = &mut self.buf;

        data.take(len as u64).read_to_string(&mut value)?;

        Ok(value)
    }

    pub fn read_ebitmap(&mut self) -> Result<Bitmap, ReadError> {
        let map_size = self.read_u32()?;
        let high_bit = self.read_u32()?;
        let map_count = self.read_u32()?;
        let mut bitmap = Bitmap::create_with_capacity(map_count);

        for map_idx in 0..map_count {
            let start_bit = self.read_u32()?;
            let map = self.read_u64()?;

            for bit in 0..64 {
                if (1 << bit) & map != 0 {
                    bitmap.add(start_bit + bit as u32);
                }
            }
        }

        Ok(bitmap)
    }

    pub fn read_policy(&mut self) -> Result<Policy, ReadError> {
        let ty_opcode = self.read_u32()?;
        let platform_str_len = self.read_u32()?;
        let platform = self.read_string(platform_str_len as usize)?;

        // If the policy file is a module there will be an additional entry
        // present indicating if it's the base module.
        let is_base_module = ty_opcode == SELINUX_MOD_MAGIC_NUMBER && self.read_u32()? == 1;

        let version = self.read_u32()?;
        let config = self.read_u32()?;
        let num_sym_tables = self.read_u32()?;
        let num_ocon_tables = self.read_u32()?;

        let ty = match ty_opcode {
            SELINUX_MAGIC_NUMBER => PolicyType::Kernel(match platform.as_str() {
                PLATFORM_SELINUX => PolicyTargetPlatform::SELinux,
                PLATFORM_XEN => PolicyTargetPlatform::Xen,
                _ => return Err(ReadError::InvalidTargetPlatform(platform)),
            }),
            SELINUX_MOD_MAGIC_NUMBER => {
                let name_len = self.read_u32()?;
                let name = self.read_string(name_len as usize)?;
                let version_len = self.read_u32()?;
                let version = self.read_string(version_len as usize)?;

                PolicyType::Module {
                    is_base_module,
                    name,
                    version,
                }
            }
            _ => return Err(ReadError::InvalidMagicCode(ty_opcode)),
        };

        let profile =
            CompatibilityProfile::find(&ty, version).ok_or(ReadError::InvalidVersion(version))?;

        let polcaps = self.read_policy_capabilities(&profile)?;
        let permissive_type_map = if profile.supports(Feature::PermissiveTypes) {
            Some(self.read_ebitmap()?)
        } else {
            None
        };

        let mut symtab_info = vec![];
        for symtab_id in 0..num_sym_tables {
            let num_primary_names = self.read_u32()?;
            let num_elements = self.read_u32()?;

            symtab_info.push((num_primary_names, num_elements));
        }

        Ok(Policy {
            ty,
            version,
            polcaps,
            profile,
        })
    }

    pub fn read_policy_capabilities(
        &mut self,
        profile: &CompatibilityProfile,
    ) -> Result<PolicyCapabilitySet, ReadError> {
        if profile.supports(Feature::PolicyCapabilities) {
            let bitmap = self.read_ebitmap()?;
            let mut polcaps = vec![];

            for polcap in bitmap.iter().map(|f| PolicyCapability::from_id(f)) {
                match polcap {
                    Some(p) => polcaps.push(p),
                    None => return Err(ReadError::InvalidPolicyCapability),
                }
            }

            Ok(PolicyCapabilitySet::new(polcaps))
        } else {
            Ok(PolicyCapabilitySet::empty())
        }
    }
}
