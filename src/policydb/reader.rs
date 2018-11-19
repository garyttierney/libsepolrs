use byteorder::{LittleEndian, ReadBytesExt};
use croaring::Bitmap;
use policydb::class::Class;
use policydb::class::Common;
use policydb::conditional::Boolean;
use policydb::cons::constants;
use policydb::cons::BinaryOp;
use policydb::cons::Constraint;
use policydb::cons::ConstraintExpression;
use policydb::cons::ConstraintExpressionKind;
use policydb::cons::UnaryOp;
use policydb::constants::*;
use policydb::mls::Category;
use policydb::mls::Sensitivity;
use policydb::polcap::{PolicyCapability, PolicyCapabilitySet};
use policydb::profile::CompatibilityProfile;
use policydb::profile::Feature;
use policydb::role::Role;
use policydb::symtable::Symbol;
use policydb::symtable::SymbolTable;
use policydb::ty::Type;
use policydb::ty::TypeSet;
use policydb::user::User;
use policydb::PolicyObject;
use policydb::{Policy, PolicyTargetPlatform, PolicyType};
use std::error::Error;
use std::fmt;
use std::io::Error as IoError;
use std::io::Read;
use std::str;
use policydb::avtab::AccessVectorTable;

/// Decodes the policy representation from a binary format.
pub struct Reader<R: Read> {
    buf: R,
    profile: Option<CompatibilityProfile>,
}

#[derive(Debug)]
pub enum ReadError {
    InvalidAccessVectorSpecifier,
    InvalidMagicCode(u32),
    InvalidPolicyCapability,
    InvalidTargetPlatform(String),
    InvalidVersion(u32),
    InputError(IoError),
    UnsupportedFeatureUsed(Feature),
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
        Reader { buf, profile: None }
    }

    pub fn read_u8(&mut self) -> Result<u8, IoError> {
        self.buf.read_u8()
    }

    pub fn read_u16(&mut self) -> Result<u16, IoError> {
        self.buf.read_u16::<LittleEndian>()
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

    pub fn read_bare_symbol_table<S>(&mut self, nel: usize) -> Result<SymbolTable<S>, ReadError>
    where
        S: Symbol,
    {
        let mut table = SymbolTable::with_capacity(nel);

        for el in 0..nel {
            table.insert(S::decode(self)?);
        }

        Ok(table)
    }

    pub fn read_symbol_table<S>(&mut self) -> Result<SymbolTable<S>, ReadError>
    where
        S: Symbol,
    {
        let _num_primary_names = self.read_u32()?;
        let num_elements = self.read_u32()?;
        let profile = self.profile();

        self.read_bare_symbol_table(num_elements as usize)
    }

    pub fn read_object<O: PolicyObject>(&mut self) -> Result<O, ReadError> {
        O::decode(self)
    }

    pub fn read_objects<O: PolicyObject>(&mut self, count: usize) -> Result<Vec<O>, ReadError> {
        let profile = self.profile();
        let mut list = Vec::with_capacity(count);

        for _ in 0..count {
            list.push(O::decode(self)?);
        }

        Ok(list)
    }

    pub fn read_policy(mut self) -> Result<Policy, ReadError> {
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

        self.profile = Some(CompatibilityProfile::new(ty, version));

        let polcaps: PolicyCapabilitySet = self.read_object()?;
        let permissive_type_map: Option<Bitmap> =
            if self.profile().supports(Feature::PermissiveTypes) {
                Some(self.read_object()?)
            } else {
                None
            };

        let common_classes: SymbolTable<Common> = self.read_symbol_table()?;
        let classes: SymbolTable<Class> = self.read_symbol_table()?;
        let roles: SymbolTable<Role> = self.read_symbol_table()?;
        let types: SymbolTable<Type> = self.read_symbol_table()?;
        let users: SymbolTable<User> = self.read_symbol_table()?;
        let booleans: SymbolTable<Boolean> = self.read_symbol_table()?;
        let sensitivities: SymbolTable<Sensitivity> = self.read_symbol_table()?;
        let categories: SymbolTable<Category> = self.read_symbol_table()?;
        let avtab: AccessVectorTable = self.read_object()?;

        Ok(Policy {
            version,
            polcaps,
            profile: self.profile.expect("uninitialized"),
            avtab,
            booleans,
            categories,
            common_classes,
            classes,
            roles,
            sensitivities,
            types,
            users,
        })
    }

    pub fn profile(&self) -> &CompatibilityProfile {
        self.profile
            .as_ref()
            .expect("Compatibility profile is uninitialized")
    }
}
