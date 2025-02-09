#[no_mangle]
pub extern "C" fn allocate_and_write(size: u32) -> *mut u8 {
    // Allocate memory
    let vec = vec![0u8; size as usize];
    let ptr = vec.as_ptr() as u32;
    
    // Prevent vec from being dropped
    std::mem::forget(vec);
    
    ptr as *mut u8
}

#[no_mangle]
pub extern "C" fn read_and_sum(ptr: *const u8, size: u32) -> u32 {
    let slice = unsafe {
        std::slice::from_raw_parts(ptr, size as usize)
    };
    
    slice.iter().map(|&x| x as u32).sum()
}
