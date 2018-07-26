use policydb::reader::ReadError;
use policydb::Reader;
use std::collections::btree_map::Values;
use std::collections::BTreeMap;
use std::io::Read;

pub trait Symbol: Sized {
    fn id(&self) -> u32;

    fn name(&self) -> &str;

    fn decode<R: Read>(reader: &mut Reader<R>) -> Result<Self, ReadError>;

    //  fn encode(writer: &mut writer) -> Result<Self, WriteError>;
}

#[derive(Debug)]
pub struct SymbolTable<SymbolType: Symbol> {
    name_id_map: BTreeMap<String, u32>,
    symbols: BTreeMap<u32, SymbolType>,
}

impl<SymbolType: Symbol> SymbolTable<SymbolType> {
    pub fn with_capacity(capacity: usize) -> Self {
        SymbolTable {
            name_id_map: BTreeMap::new(),
            symbols: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, sym: SymbolType) {
        let id = sym.id();

        self.name_id_map.insert(sym.name().to_string(), id);
        self.symbols.insert(id, sym);
    }

    pub fn all(&self) -> Values<u32, SymbolType> {
        self.symbols.values()
    }
}
