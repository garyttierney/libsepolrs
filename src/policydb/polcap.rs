use croaring::Bitmap;
use policydb::profile::CompatibilityProfile;
use policydb::profile::Feature;
use policydb::reader::ReadError;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;
use std::str::FromStr;

macro_rules! polcaps (
    (
        pub enum $name:ident {
            $($variant:ident($id:expr, $desc:expr)),*,
        }
    ) => {
        #[derive(Debug, Eq, PartialEq)]
        pub enum $name {
            $($variant),*,
        }

        impl $name {
            pub fn id(&self) -> u32 {
                match *self {
                    $($name::$variant => $id),*,
                }
            }

            pub fn from_id(id: u32) -> Option<Self> {
                match id {
                    $($id => Some($name::$variant)),*,
                    _ => None
                }
            }
        }

        impl ToString for $name {
            fn to_string(&self) -> String {
                match *self {
                    $($name::$variant => $desc.to_owned()),*,
                }
            }
        }

        impl FromStr for $name {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
                match s {
                    $($desc => Ok($name::$variant)),*,
                    _ => Err(())
                }
            }
        }
    };
);

polcaps!(pub enum PolicyCapability {
    NetworkPeerControls(0, "network_peer_controls"),
    CheckOpenPermission(1, "open_perm"),
    ExtendedSocketClasses(2, "extended_socket_class"),
    CheckNetworkPermissionAlways(3, "always_check_network"),
    CgroupSecLabel(4, "cgroup_seclabel"),
    NnpNoSuidTransition(5, "nnp_nosuid_transition"),
});

#[derive(Debug)]
pub struct PolicyCapabilitySet {
    polcaps: Vec<PolicyCapability>,
}

impl PolicyCapabilitySet {
    pub fn new(polcaps: Vec<PolicyCapability>) -> Self {
        PolicyCapabilitySet { polcaps }
    }

    pub fn empty() -> Self {
        PolicyCapabilitySet {
            polcaps: Vec::new(),
        }
    }

    pub fn all(&self) -> &[PolicyCapability] {
        &self.polcaps
    }

    pub fn is_enabled(&self, polcap: PolicyCapability) -> bool {
        self.polcaps.contains(&polcap)
    }

    pub fn enable(&mut self, polcap: PolicyCapability) {
        self.polcaps.push(polcap)
    }

    pub fn disable(&mut self, polcap: PolicyCapability) {
        if let Some(index) = self.polcaps.iter().position(|p| p == &polcap) {
            self.polcaps.remove(index);
        }
    }
}

impl PolicyObject for PolicyCapabilitySet {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let profile = reader.profile();

        if profile.supports(Feature::PolicyCapabilities) {
            let bitmap: Bitmap = reader.read_object()?;
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
