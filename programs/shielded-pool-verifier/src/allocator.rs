//! Free-able freelist allocator for the verifier-program BPF heap.
//!
//! Replaces Pinocchio's default bump allocator (which never frees) with a
//! simple singly-linked first-fit freelist that supports `dealloc` and
//! coalesces adjacent free blocks. Same heap region (`HEAP_START_ADDRESS`,
//! `MAX_HEAP_LENGTH`) - only the in-region bookkeeping changes.
//!
//! Wins:
//!  * Vec churn inside `verify()` no longer accumulates - drop-reuse works.
//!  * Larger / batched circuits that previously blew the bump-allocator
//!    high-water mark now fit.
//!  * Programs doing multiple CPI-driven verifies in one tx no longer
//!    leak heap across calls.
//!
//! Design (single-threaded - BPF entrypoint is the only consumer):
//!  * The allocator struct itself is **state-less** (matches Pinocchio's
//!    `BumpAllocator` pattern: read-only constants, no `.bss` section).
//!    The SBPF ELF loader rejects writable `.bss`, so we cannot keep
//!    `UnsafeCell<Inner>` inside the static.
//!  * All mutable state lives **inside the BPF heap region itself.**
//!    First `size_of::<*mut Header>()` bytes of the heap hold the
//!    free-list head pointer; the runtime zero-inits the heap, so
//!    `*head == null` on first call signals uninitialized state.
//!  * Block header (16 B): `size: usize` + `next: *mut Header`.
//!  * `alloc`: walks the list, first-fit, splits if the block is bigger
//!    than `needed + HEADER + MIN_REMAINDER`.
//!  * `dealloc`: inserts the block at the sorted (by address) position
//!    and coalesces with the immediate predecessor / successor if
//!    adjacent.
//!  * Lazy init on first `alloc`: writes "one giant free block" header
//!    starting at `HEAP_START + HEAD_SLOT_BYTES`.
//!
//! Safety: BPF programs are single-threaded per invocation. No locking
//! needed; no preemption inside an instruction handler.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

/// Solana BPF VM heap base. Matches Pinocchio's `HEAP_START_ADDRESS`.
pub const HEAP_START: usize = 0x300000000;
/// Maximum heap length runtime may request via `request_heap_frame`.
/// Matches Pinocchio's `MAX_HEAP_LENGTH` (256 KB).
pub const MAX_HEAP_LEN: usize = 256 * 1024;

/// One slot at the heap base stores the freelist head pointer. The rest
/// of the heap is the allocatable region. 8 bytes on the 64-bit BPF VM.
const HEAD_SLOT_BYTES: usize = core::mem::size_of::<*mut BlockHeader>();

/// Block header layout. 16 bytes (size + next pointer on 64-bit BPF).
/// Stored INSIDE each free block; for allocated blocks the header stays
/// at the start (used for dealloc lookup) and the user pointer is
/// `block + sizeof(Header)`.
#[repr(C)]
struct BlockHeader {
    /// Total size of this block in bytes, including the header itself.
    size: usize,
    /// Next free block (singly-linked list, sorted by address) or null.
    /// Meaningful only while the block is free.
    next: *mut BlockHeader,
}

const HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();

/// Smallest free remainder we'll bother splitting off - anything smaller
/// stays attached to the user's allocation and is wasted as internal
/// fragmentation. 32 bytes is large enough to hold a (header + a single
/// `Fr` or pointer) follow-up alloc.
const MIN_REMAINDER: usize = 32;

/// Stateless allocator handle. All mutable state lives in the BPF heap
/// region at `HEAP_START`. This keeps the `#[global_allocator]` static
/// fully read-only (no `.bss` writable section in the ELF), which the
/// SBPF loader requires.
pub struct FreelistAllocator;

// Safety: stateless - no mutable members.
unsafe impl Sync for FreelistAllocator {}

impl FreelistAllocator {
    pub const fn new() -> Self {
        FreelistAllocator
    }
}

/// Round `n` up to the next multiple of `align`. `align` must be a power of two.
#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Read the freelist head pointer from `HEAP_START`. The BPF runtime
/// zero-inits the heap, so on first call we observe `null` and lazy-init
/// the initial "one giant free block".
#[inline]
unsafe fn head_slot() -> *mut *mut BlockHeader {
    HEAP_START as *mut *mut BlockHeader
}

#[inline]
unsafe fn lazy_init() {
    let first_block = (HEAP_START + HEAD_SLOT_BYTES) as *mut BlockHeader;
    let region_size = MAX_HEAP_LEN - HEAD_SLOT_BYTES;
    (*first_block).size = region_size;
    (*first_block).next = null_mut();
    *head_slot() = first_block;
}

unsafe impl GlobalAlloc for FreelistAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Lazy init on first call: head_slot is null → install initial block.
        if (*head_slot()).is_null() {
            lazy_init();
        }

        // Needed bytes = header + user payload, rounded to header
        // alignment (16 B) so subsequent block headers stay aligned.
        let align = layout.align().max(HEADER_SIZE);
        let payload = align_up(layout.size(), align);
        let needed = HEADER_SIZE + payload;

        // First-fit walk over the free list.
        let mut prev_link: *mut *mut BlockHeader = head_slot();
        loop {
            let block = *prev_link;
            if block.is_null() {
                return null_mut(); // OOM
            }
            let block_size = (*block).size;
            if block_size >= needed {
                if block_size >= needed + HEADER_SIZE + MIN_REMAINDER {
                    // Split: carve off the remainder as its own free block.
                    let remainder = (block as *mut u8).add(needed) as *mut BlockHeader;
                    (*remainder).size = block_size - needed;
                    (*remainder).next = (*block).next;
                    *prev_link = remainder;
                    (*block).size = needed; // record actual size for dealloc
                } else {
                    // Use whole block; unlink it.
                    *prev_link = (*block).next;
                    // (*block).size stays at block_size.
                }
                return (block as *mut u8).add(HEADER_SIZE);
            }
            prev_link = &mut (*block).next as *mut _;
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            core::ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let block = (ptr as *mut u8).sub(HEADER_SIZE) as *mut BlockHeader;
        let block_size = (*block).size;

        // Find sorted insertion point - sorted by address makes
        // coalescing with neighbors a single forward check.
        let mut prev_link: *mut *mut BlockHeader = head_slot();
        loop {
            let cur = *prev_link;
            if cur.is_null() || (cur as usize) > (block as usize) {
                (*block).next = cur;
                *prev_link = block;
                break;
            }
            prev_link = &mut (*cur).next as *mut _;
        }

        // Coalesce with next if adjacent.
        let next = (*block).next;
        if !next.is_null() && (block as *mut u8).add(block_size) as *mut BlockHeader == next {
            (*block).size = block_size + (*next).size;
            (*block).next = (*next).next;
        }

        // Coalesce with previous if adjacent. Rare-path re-walk from
        // head; cheap on a typical free list of a few entries.
        let mut walk: *mut *mut BlockHeader = head_slot();
        while !(*walk).is_null() {
            let cand = *walk;
            if cand == block {
                break;
            }
            let cand_end = (cand as *mut u8).add((*cand).size) as *mut BlockHeader;
            if cand_end == block {
                (*cand).size += (*block).size;
                (*cand).next = (*block).next;
                break;
            }
            walk = &mut (*cand).next as *mut _;
        }
    }
}

// ---------------------------------------------------------------------------
// Host-side unit tests - algorithm-level only. Full BPF VM coverage lives
// in the Mollusk integration tests against every reference circuit.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        // 16 bytes on 64-bit (where BPF runs): size (8) + next (8).
        assert_eq!(HEADER_SIZE, 16);
        assert_eq!(MIN_REMAINDER, 32);
    }

    #[test]
    fn align_up_basic() {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(7, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 16), 16);
        assert_eq!(align_up(15, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
    }

    #[test]
    fn allocator_is_stateless() {
        // Sanity: zero-sized handle. If this ever grows (e.g., adding
        // a backing-store pointer), it'd want a writable section and
        // would break the SBPF loader.
        assert_eq!(core::mem::size_of::<FreelistAllocator>(), 0);
    }
}
