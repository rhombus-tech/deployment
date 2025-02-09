#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{memory::MemorySafetyProperty, Property};
    use wasmparser::WasmFeatures;

    #[test]
    fn test_memory_safety_verification() {
        let wasm_bytes = wat::parse_str(
            r#"
            (module
                (memory 1)
                (func (export "test")
                    i32.const 0
                    i32.load
                    drop
                )
            )
            "#,
        ).unwrap();

        let property = MemorySafetyProperty;
        let features = WasmFeatures::default();
        let proof = property.verify(&wasm_bytes, &features).unwrap();
        
        assert!(proof.bounds_checked);
        assert!(proof.leak_free);
        assert!(proof.access_safety);
        assert!(!proof.memory_accesses.is_empty());
    }
}
