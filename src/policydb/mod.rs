use policydb::class::Class;
use policydb::class::Common;
use policydb::polcap::PolicyCapabilitySet;
use policydb::profile::CompatibilityProfile;
use policydb::reader::ReadError;
pub use policydb::reader::Reader;
use policydb::role::Role;
use policydb::symtable::SymbolTable;
use policydb::ty::Type;
use std::io::Read;

pub mod bitmap;
pub mod class;
pub mod cons;
pub mod mls;
pub mod polcap;
pub mod profile;
pub mod reader;
pub mod role;
pub mod symtable;
pub mod ty;
pub mod user;

pub(crate) mod constants {
    pub(crate) const PLATFORM_SELINUX: &str = "SE Linux";

    pub(crate) const PLATFORM_XEN: &str = "XenFlask";

    pub(crate) const SELINUX_MAGIC_NUMBER: u32 = 0xf97cff8c;

    pub(crate) const SELINUX_MOD_MAGIC_NUMBER: u32 = 0xf97cff8d;

    pub(crate) const CONFIG_MLS_ENABLED: u32 = 0x00000001;

    pub(crate) const CONFIG_REJECT_UNKNOWN: u32 = 0x00000002;

    pub(crate) const CONFIG_ALLOW_UNKNOWN: u32 = 0x00000004;
}

pub enum PolicyError {}

#[derive(Debug)]
pub struct Policy {
    version: u32,
    polcaps: PolicyCapabilitySet,
    profile: CompatibilityProfile,
    common_classes: SymbolTable<Common>,
    classes: SymbolTable<Class>,
    roles: SymbolTable<Role>,
    types: SymbolTable<Type>,
}

pub trait PolicyObject: Sized {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError>;

    fn decode_collection<R: Read>(
        reader: &mut Reader<R>,
        profile: &CompatibilityProfile,
        count: usize,
    ) -> Result<Vec<Self>, ReadError> {
        let mut collection: Vec<Self> = Vec::with_capacity(count);

        for _ in 0..count {
            collection.push(Self::decode(reader)?);
        }

        Ok(collection)
    }
}

impl Policy {
    pub fn common_classes(&self) -> &SymbolTable<Common> {
        &self.common_classes
    }

    pub fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }

    pub fn polcaps(&self) -> &PolicyCapabilitySet {
        &self.polcaps
    }

    pub fn ty(&self) -> &PolicyType {
        &self.profile.ty()
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyTargetPlatform {
    SELinux,
    Xen,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyType {
    Kernel(PolicyTargetPlatform),
    Module {
        is_base_module: bool,
        name: String,
        version: String,
    },
}

impl PolicyType {
    pub fn is_kernel_policy(&self) -> bool {
        match *self {
            PolicyType::Kernel(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub mls_enabled: bool,
    pub allow_unknowns: bool,
}
