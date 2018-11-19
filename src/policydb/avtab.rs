use policydb::PolicyObject;
use policydb::profile::Feature;
use policydb::Reader;
use policydb::reader::ReadError;
use std::io::Read;

bitflags! {
    struct AccessVectorSpecifier : u16 {
        const AVTAB_ALLOWED = 0x0001;
        const AVTAB_AUDITALLOW  = 0x0002;
        const AVTAB_AUDITDENY = 0x0004;
        const AVTAB_NEVERALLOW = 0x0080;
        const AVTAB_AV = (Self::AVTAB_ALLOWED.bits | Self::AVTAB_AUDITALLOW.bits | Self::AVTAB_AUDITDENY.bits);

        const AVTAB_TRANSITION  = 0x0010;
        const AVTAB_MEMBER = 0x0020;
        const AVTAB_CHANGE = 0x0040;
        const AVTAB_TYPE = (Self::AVTAB_TRANSITION.bits | Self::AVTAB_MEMBER.bits | Self::AVTAB_CHANGE.bits);

        const AVTAB_XPERMS_ALLOWED = 0x0100;
        const AVTAB_XPERMS_AUDITALLOW = 0x0200;
        const AVTAB_XPERMS_DONTAUDIT = 0x0400;
        const AVTAB_XPERMS_NEVERALLOW = 0x0800;
        const AVTAB_XPERMS = (Self::AVTAB_XPERMS_ALLOWED.bits | Self::AVTAB_XPERMS_AUDITALLOW.bits | Self::AVTAB_XPERMS_DONTAUDIT.bits);

        const AVTAB_ENABLED = 0x8000;  /* reserved for used in cond_avtab */
        const AVTAB_ANY = (Self::AVTAB_TYPE.bits | Self::AVTAB_AV.bits);
    }
}

lazy_static! {
    static ref LEGACY_AV_SPECIFIERS: Vec<AccessVectorSpecifier> = {
        let mut list = Vec::new();
        list.push(AccessVectorSpecifier::AVTAB_ALLOWED);
        list.push(AccessVectorSpecifier::AVTAB_AUDITDENY);
        list.push(AccessVectorSpecifier::AVTAB_AUDITALLOW);
        list.push(AccessVectorSpecifier::AVTAB_TRANSITION);
        list.push(AccessVectorSpecifier::AVTAB_CHANGE);
        list.push(AccessVectorSpecifier::AVTAB_MEMBER);
        list.push(AccessVectorSpecifier::AVTAB_XPERMS_ALLOWED);
        list.push(AccessVectorSpecifier::AVTAB_XPERMS_AUDITALLOW);
        list.push(AccessVectorSpecifier::AVTAB_XPERMS_DONTAUDIT);
        list
    };
}

const AVTAB_ENABLED_OLD: u32 = 0x80000000;

#[derive(Debug, Hash)]
pub struct AccessVectorTableKey {
    source_type: u16,
    target_type: u16,
    target_class: u16,
    specifier: AccessVectorSpecifier,
}

#[derive(Debug)]
pub struct AccessVectorTableEntry {
    key: AccessVectorTableKey,
    av: AccessVector,
}

#[derive(Debug)]
pub struct AccessVectorTable {
    entries: Vec<AccessVectorTableEntry>
}

#[derive(Debug)]
pub enum AccessVector {
    Simple(u32),
    Extended {
        specified: u8,
        driver: u8,
        permissions: [u32; 8],
    },
}

impl PolicyObject for AccessVectorTable {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let num_entries = reader.read_u32()? as usize;
        let mut entries: Vec<AccessVectorTableEntry> = Vec::with_capacity(num_entries);
        let is_xavtab_supported = reader.profile().supports(Feature::AvTab);

        for _ in 0..num_entries {
            if !is_xavtab_supported {
                let items2 /*???*/ = reader.read_u32()?;
                let source_type = reader.read_u32()? as u16;
                let target_type = reader.read_u32()? as u16;
                let target_class = reader.read_u32()? as u16;

                let specifier_val = reader.read_u32()?;
                let enabled = if (specifier_val & AVTAB_ENABLED_OLD) == 0 {
                    AccessVectorSpecifier::empty()
                } else {
                    AccessVectorSpecifier::AVTAB_ENABLED
                };

                for target_specifier in LEGACY_AV_SPECIFIERS.iter() {
                    if target_specifier.bits & specifier_val as u16 != 0 {
                        let datum = reader.read_u32()?;

                        entries.push(AccessVectorTableEntry {
                            key: AccessVectorTableKey {
                                source_type,
                                target_type,
                                target_class,
                                specifier: *target_specifier | enabled,
                            },
                            av: AccessVector::Simple(datum),
                        })
                    }
                }
            } else {
                let source_type = reader.read_u16()?;
                let target_type = reader.read_u16()?;
                let target_class = reader.read_u16()?;
                let specifier = AccessVectorSpecifier::from_bits(reader.read_u16()?)
                    .ok_or(ReadError::InvalidAccessVectorSpecifier)?;
                let matching_specifiers = LEGACY_AV_SPECIFIERS
                    .iter()
                    .filter(|s| specifier.contains(**s))
                    .count();

                if matching_specifiers > 1 {
                    return Err(ReadError::InvalidAccessVectorSpecifier);
                }

                let ioctls_supported = reader.profile().supports(Feature::XpermsIoctl);
                let extended_av = specifier.contains(AccessVectorSpecifier::AVTAB_XPERMS);

                let av = if !ioctls_supported && extended_av {
                    return Err(ReadError::UnsupportedFeatureUsed(Feature::XpermsIoctl));
                } else if extended_av {
                    let specified = reader.read_u8()?;
                    let driver = reader.read_u8()?;
                    let mut permissions = [0; 8];

                    for idx in 0..8 {
                        permissions[idx] = reader.read_u32()?;
                    }

                    AccessVector::Extended {
                        specified,
                        driver,
                        permissions,
                    }
                } else {
                    AccessVector::Simple(reader.read_u32()?)
                };

                entries.push(AccessVectorTableEntry {
                    key: AccessVectorTableKey {
                        source_type,
                        target_type,
                        target_class,
                        specifier,
                    },
                    av,
                })
            }
        }

        Ok(AccessVectorTable { entries })
    }
}
