pub mod class;
pub mod feature;
pub mod polcap;
pub mod profile;
pub mod reader;
pub mod symtable;

use policydb::class::Common;
use policydb::polcap::PolicyCapabilitySet;
use policydb::profile::CompatibilityProfile;
pub use policydb::reader::Reader;
use policydb::symtable::SymbolTable;

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

pub struct Policy {
    ty: PolicyType,
    version: u32,
    polcaps: PolicyCapabilitySet,
    profile: CompatibilityProfile,
    common_classes: SymbolTable<Common>,
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
        &self.ty
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyTargetPlatform {
    SELinux,
    Xen,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyType {
    Kernel(PolicyTargetPlatform),
    Module {
        is_base_module: bool,
        name: String,
        version: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub mls_enabled: bool,
    pub allow_unknowns: bool,
}
