use croaring::Bitmap;
use policydb::profile::CompatibilityProfile;
use policydb::reader::ReadError;
use policydb::ty::TypeSet;
use policydb::PolicyObject;
use policydb::Reader;
use std::io::Read;

pub(crate) mod constants {
    pub const CEXPR_NOT: u32 = 1; /* not expr */
    pub const CEXPR_AND: u32 = 2; /* expr and expr */
    pub const CEXPR_OR: u32 = 3; /* expr or expr */
    pub const CEXPR_ATTR: u32 = 4; /* attr op attr */
    pub const CEXPR_NAMES: u32 = 5; /* attr op names */
}

#[derive(Debug)]
pub struct Constraint {
    pub(crate) permissions: u32,
    pub(crate) expressions: Vec<ConstraintExpression>,
}

#[derive(Debug)]
pub enum UnaryOp {
    Not,
}

#[derive(Debug)]
pub enum BinaryOp {
    And,
    Or,
}

#[derive(Debug)]
pub struct ConstraintExpression {
    pub(crate) op: u32,
    pub(crate) attr: u32,
    pub(crate) kind: ConstraintExpressionKind,
}

#[derive(Debug)]
pub enum ConstraintExpressionKind {
    Unary(UnaryOp),
    Binary(BinaryOp),
    Attr,
    Names {
        names: Bitmap,
        type_names: Option<TypeSet>,
    },
}

impl PolicyObject for Constraint {
    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError> {
        let permissions = reader.read_u32()?;
        let num_exprs = reader.read_u32()? as usize;
        let mut expressions: Vec<ConstraintExpression> = Vec::with_capacity(num_exprs);

        for _ in 0..num_exprs {
            let expr_ty = reader.read_u32()?;
            let attr = reader.read_u32()?;
            let op = reader.read_u32()?;

            let kind = match expr_ty {
                constants::CEXPR_NOT => ConstraintExpressionKind::Unary(UnaryOp::Not),
                constants::CEXPR_AND => ConstraintExpressionKind::Binary(BinaryOp::And),
                constants::CEXPR_OR => ConstraintExpressionKind::Binary(BinaryOp::Or),
                constants::CEXPR_ATTR => ConstraintExpressionKind::Attr,
                constants::CEXPR_NAMES => {
                    let names = reader.read_object()?;
                    let types = reader.read_object()?;
                    let inverse_types = reader.read_object()?;
                    let flags = reader.read_u32()?;
                    let type_names = Some(TypeSet::Set {
                        flags,
                        types,
                        inverse_types,
                    });

                    ConstraintExpressionKind::Names { names, type_names }
                }
                _ => return Err(ReadError::InvalidPolicyCapability),
            };

            expressions.push(ConstraintExpression { op, attr, kind });
        }

        Ok(Constraint {
            permissions,
            expressions,
        })
    }
}
