use super::FDESearchResult;
use crate::util::*;
use crate::baremetal_debug::unwinding_debugln;

use gimli::{BaseAddresses, EhFrame, EhFrameHdr, NativeEndian, UnwindSection};

pub struct StaticFinder(());

pub fn get_finder() -> &'static StaticFinder {
    &StaticFinder(())
}

unsafe extern "C" {
    static __executable_start: u8;
    static __etext: u8;
    static __GNU_EH_FRAME_HDR: u8;
}

impl super::FDEFinder for StaticFinder {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        unwinding_debugln!("StaticFinder::find_fde: searching for PC 0x{:x}", pc);
        unsafe {
            let text_start = &__executable_start as *const u8 as usize;
            let text_end = &__etext as *const u8 as usize;
            unwinding_debugln!("StaticFinder::find_fde: text range 0x{:x}-0x{:x}", text_start, text_end);
            if !(text_start..text_end).contains(&pc) {
                unwinding_debugln!("StaticFinder::find_fde: PC 0x{:x} not in text range", pc);
                return None;
            }
            unwinding_debugln!("StaticFinder::find_fde: PC 0x{:x} in text range", pc);

            let eh_frame_hdr = &__GNU_EH_FRAME_HDR as *const u8 as usize;
            unwinding_debugln!("StaticFinder::find_fde: eh_frame_hdr at 0x{:x}", eh_frame_hdr);
            let bases = BaseAddresses::default()
                .set_text(text_start as _)
                .set_eh_frame_hdr(eh_frame_hdr as _);
            let eh_frame_hdr =
                EhFrameHdr::new(get_unlimited_slice(eh_frame_hdr as _), NativeEndian)
                    .parse(&bases, core::mem::size_of::<usize>() as _)
                    .ok()?;
            let eh_frame = deref_pointer(eh_frame_hdr.eh_frame_ptr());
            unwinding_debugln!("StaticFinder::find_fde: eh_frame at 0x{:x}", eh_frame);
            let bases = bases.set_eh_frame(eh_frame as _);
            let eh_frame = EhFrame::new(get_unlimited_slice(eh_frame as _), NativeEndian);

            // Use binary search table for address if available.
            if let Some(table) = eh_frame_hdr.table() {
                unwinding_debugln!("StaticFinder::find_fde: using binary search table");
                if let Ok(fde) =
                    table.fde_for_address(&eh_frame, &bases, pc as _, EhFrame::cie_from_offset)
                {
                    unwinding_debugln!("StaticFinder::find_fde: found FDE via binary search table");
                    return Some(FDESearchResult {
                        fde,
                        bases,
                        eh_frame,
                    });
                } else {
                    unwinding_debugln!("StaticFinder::find_fde: binary search table failed");
                }
            } else {
                unwinding_debugln!("StaticFinder::find_fde: no binary search table available");
            }

            // Otherwise do the linear search.
            unwinding_debugln!("StaticFinder::find_fde: trying linear search");
            if let Ok(fde) = eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset) {
                unwinding_debugln!("StaticFinder::find_fde: found FDE via linear search");
                return Some(FDESearchResult {
                    fde,
                    bases,
                    eh_frame,
                });
            } else {
                unwinding_debugln!("StaticFinder::find_fde: linear search failed");
            }

            unwinding_debugln!("StaticFinder::find_fde: no FDE found");
            None
        }
    }
}
