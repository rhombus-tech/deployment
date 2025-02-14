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

#[no_mangle]
pub extern "C" fn vulnerable_copy(src: *const u8, dst: *mut u8, size: u32) {
    // This is vulnerable! We don't check if the memory regions overlap
    // or if we have enough space in the destination
    unsafe {
        let src_slice = std::slice::from_raw_parts(src, size as usize);
        let dst_slice = std::slice::from_raw_parts_mut(dst, size as usize);
        dst_slice.copy_from_slice(src_slice);
    }
}

#[no_mangle]
pub extern "C" fn vulnerable_increment(ptr: *mut u8, size: u32) {
    // This is vulnerable! We don't check if we're accessing valid memory
    unsafe {
        // Try to increment each byte, might access invalid memory
        for i in 0..size {
            let byte_ptr = ptr.add(i as usize);
            *byte_ptr = byte_ptr.read().wrapping_add(1);
        }
    }
}
