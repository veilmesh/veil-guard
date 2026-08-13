#![no_std]
#![no_main]

use core::panic::PanicInfo;
use sha2::{Digest, Sha256};

// ── Public ABI ──────────────────────────────────────────────────────────────
//
// JS side allocates `hasher_size()` bytes of WASM linear memory and passes the
// pointer into every call. The Rust side is fully stateless: no globals, no
// allocator. Multiple concurrent hashers are supported — each has its own slot.
//
// Contract enforced by this module:
//   - Call hasher_init before the first hasher_update.
//   - Call hasher_finalize exactly once. After it returns, the slot is zeroed;
//     a second call will produce all-zero output rather than undefined behaviour.

/// Size in bytes of the Sha256 state struct. JS must allocate at least this
/// many bytes and pass the pointer to all other functions.
#[no_mangle]
pub extern "C" fn hasher_size() -> usize {
    core::mem::size_of::<Sha256>()
}

extern "C" {
    /// Defined by wasm-ld: the first address past this module's static data and
    /// shadow stack.
    static __heap_base: u8;
}

/// The lowest address JS may write to.
///
/// Everything below is the module's own: static data — the SHA-256 round
/// constants among it — and the shadow stack that `hasher_update` pushes its
/// frame onto. A caller that allocates from address zero is writing into both,
/// and the symptom is a wrong digest rather than a trap: the round constants
/// still look like numbers, and the stack frame quietly overwrites whatever
/// input happens to occupy the same addresses.
#[no_mangle]
pub extern "C" fn hasher_heap_base() -> usize {
    // Taking the address of a linker-defined symbol; never dereferenced here.
    core::ptr::addr_of!(__heap_base) as usize
}

/// Initialise a hasher in the caller-allocated slot.
#[no_mangle]
pub extern "C" fn hasher_init(state: *mut u8) {
    // SAFETY: caller guarantees the slot is at least hasher_size() bytes.
    unsafe { core::ptr::write(state as *mut Sha256, Sha256::new()) }
}

/// Feed `len` bytes at `data` into the hasher.
#[no_mangle]
pub extern "C" fn hasher_update(state: *mut u8, data: *const u8, len: usize) {
    // SAFETY: caller owns both pointers and guarantees they are valid.
    let h = unsafe { &mut *(state as *mut Sha256) };
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    h.update(slice);
}

/// Write the 32-byte SHA-256 digest into `out`, then zero the state slot.
/// Zeroing protects against double-finalize returning stale data.
#[no_mangle]
pub extern "C" fn hasher_finalize(state: *mut u8, out: *mut u8) {
    // SAFETY: caller owns both pointers.
    let h = unsafe { core::ptr::read(state as *const Sha256) };
    let result = h.finalize();
    unsafe {
        core::ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
        // Zero the slot so a second call yields all-zero, not a use-after-move.
        core::ptr::write_bytes(state, 0, core::mem::size_of::<Sha256>());
    }
}

// ── Required by no_std + cdylib ─────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
