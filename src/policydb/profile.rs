use policydb::feature::Feature;
use policydb::PolicyTargetPlatform;
use policydb::PolicyType;

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

#[derive(Debug)]
pub struct CompatibilityProfile {
    features: HashSet<Feature>,
}

impl CompatibilityProfile {
    pub fn supports(&self, feature: Feature) -> bool {
        self.features.contains(&feature)
    }

    pub fn find(ty: &PolicyType, version: u32) -> Option<Self> {
        //@todo - make this cleaner and add conditions for all platform, type, and version permutations
        let mut feature_set: HashSet<Feature> = HashSet::new();

        match ty {
            &PolicyType::Kernel(PolicyTargetPlatform::SELinux) | &PolicyType::Module { .. } => {
                if version > POLICYDB_VERSION_POLCAP {
                    feature_set.insert(Feature::PolicyCapabilities);
                }
            }
            &PolicyType::Kernel(PolicyTargetPlatform::Xen) => {
                return None;
            }
        };

        Some(CompatibilityProfile {
            features: feature_set,
        })
    }
}
