use wasmparser::WasmFeatures;
use crate::analyzer::Property;
use anyhow::Result;

pub struct TypeCorrectnessProperty;

#[derive(Debug)]
pub struct TypeCorrectnessProof {
    pub type_safe: bool,
}

impl Property for TypeCorrectnessProperty {
    type Proof = TypeCorrectnessProof;

    fn verify(&self, _wasm: &[u8], _features: &WasmFeatures) -> Result<Self::Proof> {
        // TODO: Implement type checking
        Ok(TypeCorrectnessProof {
            type_safe: true,
        })
    }
}
