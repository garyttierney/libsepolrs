use policydb::PolicyTargetPlatform;
use policydb::PolicyType;
use std::collections::HashMap;
use std::collections::HashSet;

const POLICYDB_VERSION_BASE: u32 = 15;
const POLICYDB_VERSION_BOOL: u32 = 16;
const POLICYDB_VERSION_IPV6: u32 = 17;
const POLICYDB_VERSION_NLCLASS: u32 = 18;
const POLICYDB_VERSION_VALIDATETRANS: u32 = 19;
const POLICYDB_VERSION_MLS: u32 = 19;
const POLICYDB_VERSION_AVTAB: u32 = 20;
const POLICYDB_VERSION_RANGETRANS: u32 = 21;
const POLICYDB_VERSION_POLCAP: u32 = 22;
const POLICYDB_VERSION_PERMISSIVE: u32 = 23;
const POLICYDB_VERSION_BOUNDARY: u32 = 24;
const POLICYDB_VERSION_FILENAME_TRANS: u32 = 25;
const POLICYDB_VERSION_ROLETRANS: u32 = 26;
const POLICYDB_VERSION_NEW_OBJECT_DEFAULTS: u32 = 27;
const POLICYDB_VERSION_DEFAULT_TYPE: u32 = 28;
const POLICYDB_VERSION_CONSTRAINT_NAMES: u32 = 29;
const POLICYDB_VERSION_XEN_DEVICETREE: u32 = 30;
const POLICYDB_VERSION_XPERMS_IOCTL: u32 = 30;
const POLICYDB_VERSION_INFINIBAND: u32 = 31;

const MOD_POLICYDB_VERSION_BASE: u32 = 4;
const MOD_POLICYDB_VERSION_VALIDATETRANS: u32 = 5;
const MOD_POLICYDB_VERSION_MLS: u32 = 5;
const MOD_POLICYDB_VERSION_RANGETRANS: u32 = 6;
const MOD_POLICYDB_VERSION_MLS_USERS: u32 = 6;
const MOD_POLICYDB_VERSION_POLCAP: u32 = 7;
const MOD_POLICYDB_VERSION_PERMISSIVE: u32 = 8;
const MOD_POLICYDB_VERSION_BOUNDARY: u32 = 9;
const MOD_POLICYDB_VERSION_BOUNDARY_ALIAS: u32 = 10;
const MOD_POLICYDB_VERSION_FILENAME_TRANS: u32 = 11;
const MOD_POLICYDB_VERSION_ROLETRANS: u32 = 12;
const MOD_POLICYDB_VERSION_ROLEATTRIB: u32 = 13;
const MOD_POLICYDB_VERSION_TUNABLE_SEP: u32 = 14;
const MOD_POLICYDB_VERSION_NEW_OBJECT_DEFAULTS: u32 = 15;
const MOD_POLICYDB_VERSION_DEFAULT_TYPE: u32 = 16;
const MOD_POLICYDB_VERSION_CONSTRAINT_NAMES: u32 = 17;
const MOD_POLICYDB_VERSION_XPERMS_IOCTL: u32 = 18;
const MOD_POLICYDB_VERSION_INFINIBAND: u32 = 19;

enum FeatureRequirement {
    Version {
        kernel: Option<u32>,
        module: Option<u32>,
    },
    Platform(PolicyTargetPlatform),
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum Feature {
    PermissiveTypes,
    PolicyCapabilities,
    ValidateTransition,
    NewObjectDefaults,
    DefaultType,
    Boundary,
    BoundaryAlias,
    Mls,
    MlsUsers,
    TunableSep,
    AvTab,
    XpermsIoctl,
}

impl Feature {
    fn requirements(&self) -> Vec<FeatureRequirement> {
        fn kernel_only(ver: u32) -> FeatureRequirement {
            FeatureRequirement::Version {
                kernel: Some(ver),
                module: None,
            }
        }

        fn module_only(ver: u32) -> FeatureRequirement {
            FeatureRequirement::Version {
                kernel: None,
                module: Some(ver),
            }
        }

        fn version(kernel: u32, module: u32) -> FeatureRequirement {
            FeatureRequirement::Version {
                kernel: Some(kernel),
                module: Some(module),
            }
        }

        fn platform(platform: PolicyTargetPlatform) -> FeatureRequirement {
            FeatureRequirement::Platform(platform)
        }

        match *self {
            Feature::PolicyCapabilities => vec![version(
                POLICYDB_VERSION_POLCAP,
                MOD_POLICYDB_VERSION_POLCAP,
            )],
            Feature::PermissiveTypes => vec![version(
                POLICYDB_VERSION_PERMISSIVE,
                MOD_POLICYDB_VERSION_PERMISSIVE,
            )],
            Feature::ValidateTransition => vec![version(
                POLICYDB_VERSION_VALIDATETRANS,
                MOD_POLICYDB_VERSION_VALIDATETRANS,
            )],
            Feature::DefaultType => vec![version(
                POLICYDB_VERSION_DEFAULT_TYPE,
                MOD_POLICYDB_VERSION_DEFAULT_TYPE,
            )],
            Feature::NewObjectDefaults => vec![version(
                POLICYDB_VERSION_NEW_OBJECT_DEFAULTS,
                MOD_POLICYDB_VERSION_NEW_OBJECT_DEFAULTS,
            )],
            Feature::Boundary => vec![version(
                POLICYDB_VERSION_BOUNDARY,
                MOD_POLICYDB_VERSION_BOUNDARY,
            )],
            Feature::BoundaryAlias => vec![module_only(MOD_POLICYDB_VERSION_BOUNDARY_ALIAS)],
            Feature::Mls => vec![version(POLICYDB_VERSION_MLS, MOD_POLICYDB_VERSION_MLS)],
            Feature::MlsUsers => vec![module_only(MOD_POLICYDB_VERSION_MLS_USERS)],
            Feature::TunableSep => vec![module_only(MOD_POLICYDB_VERSION_TUNABLE_SEP)],
            Feature::AvTab => vec![kernel_only(POLICYDB_VERSION_AVTAB)],
            Feature::XpermsIoctl => vec![version(
                POLICYDB_VERSION_XPERMS_IOCTL,
                MOD_POLICYDB_VERSION_XPERMS_IOCTL,
            )],
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompatibilityProfile {
    ty: PolicyType,
    version: u32,
}

impl CompatibilityProfile {
    pub fn supports(&self, feature: Feature) -> bool {
        let is_kernel_policy = self.ty().is_kernel_policy();

        feature.requirements().iter().all(|req| match req {
            FeatureRequirement::Version {
                module: Some(ver), ..
            }
                if !is_kernel_policy =>
            {
                self.version >= *ver
            }
            FeatureRequirement::Version {
                kernel: Some(ver), ..
            }
                if is_kernel_policy =>
            {
                self.version >= *ver
            }
            _ => false,
        })
    }

    pub fn ty(&self) -> &PolicyType {
        &self.ty
    }

    pub fn new(ty: PolicyType, version: u32) -> Self {
        CompatibilityProfile { ty, version }
    }
}
