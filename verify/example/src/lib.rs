use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[wasm_bindgen]
pub fn store_and_load(value: i32, address: i32) -> i32 {
    unsafe {
        let ptr = address as *mut i32;
        *ptr = value;
        *ptr
    }
}
