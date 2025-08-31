use super::FDESearchResult;
use crate::util::*;
use crate::baremetal_debug::unwinding_debugln;

use gimli::{BaseAddresses, EhFrame, NativeEndian, UnwindSection};

pub struct StaticFinder(());

pub fn get_finder() -> &'static StaticFinder {
    &StaticFinder(())
}

unsafe extern "C" {
    static __executable_start: u8;
    static __etext: u8;
    static __eh_frame: u8;
}

impl super::FDEFinder for StaticFinder {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        unwinding_debugln!("FixedFinder::find_fde: searching for PC 0x{:x}", pc);
        unsafe {
            let text_start = &__executable_start as *const u8 as usize;
            let text_end = &__etext as *const u8 as usize;
            unwinding_debugln!("FixedFinder::find_fde: text range 0x{:x}-0x{:x}", text_start, text_end);
            if !(text_start..text_end).contains(&pc) {
                unwinding_debugln!("FixedFinder::find_fde: PC 0x{:x} not in text range", pc);
                return None;
            }
            unwinding_debugln!("FixedFinder::find_fde: PC 0x{:x} in text range", pc);

            let eh_frame = &__eh_frame as *const u8 as usize;
            unwinding_debugln!("FixedFinder::find_fde: eh_frame at 0x{:x}", eh_frame);
            let bases = BaseAddresses::default()
                .set_eh_frame(eh_frame as _)
                .set_text(text_start as _);
            let eh_frame = EhFrame::new(get_unlimited_slice(eh_frame as _), NativeEndian);

            unwinding_debugln!("FixedFinder::find_fde: searching for FDE");
            if let Ok(fde) = eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset) {
                unwinding_debugln!("FixedFinder::find_fde: found FDE");
                return Some(FDESearchResult {
                    fde,
                    bases,
                    eh_frame,
                });
            } else {
                unwinding_debugln!("FixedFinder::find_fde: no FDE found");
            }

            None
        }
    }
}
