use super::FDESearchResult;
use crate::util::get_unlimited_slice;
use crate::baremetal_debug::unwinding_debugln;
use alloc::boxed::Box;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ops;
use core::ptr;
use gimli::{BaseAddresses, EhFrame, NativeEndian, UnwindSection};

enum Table {
    Single(*const c_void),
    Multiple(*const *const c_void),
}

struct Object {
    next: *mut Object,
    tbase: usize,
    dbase: usize,
    table: Table,
}

struct GlobalState {
    object: *mut Object,
}

unsafe impl Send for GlobalState {}

pub struct Registry(());

// `unsafe` because there is no protection for reentrance.
unsafe fn lock_global_state() -> impl ops::DerefMut<Target = GlobalState> {
    #[cfg(feature = "libc")]
    {
        static mut MUTEX: libc::pthread_mutex_t = libc::PTHREAD_MUTEX_INITIALIZER;
        unsafe { libc::pthread_mutex_lock(core::ptr::addr_of_mut!(MUTEX)) };

        static mut STATE: GlobalState = GlobalState {
            object: ptr::null_mut(),
        };

        struct LockGuard;
        impl Drop for LockGuard {
            fn drop(&mut self) {
                unsafe { libc::pthread_mutex_unlock(core::ptr::addr_of_mut!(MUTEX)) };
            }
        }

        impl ops::Deref for LockGuard {
            type Target = GlobalState;

            #[allow(static_mut_refs)]
            fn deref(&self) -> &GlobalState {
                unsafe { &*core::ptr::addr_of!(STATE) }
            }
        }

        impl ops::DerefMut for LockGuard {
            fn deref_mut(&mut self) -> &mut GlobalState {
                unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
            }
        }

        LockGuard
    }
    #[cfg(not(feature = "libc"))]
    {
        static MUTEX: spin::Mutex<GlobalState> = spin::Mutex::new(GlobalState {
            object: ptr::null_mut(),
        });
        MUTEX.lock()
    }
    #[cfg(not(any(feature = "libc", feature = "spin")))]
    compile_error!("Either feature \"libc\" or \"spin\" must be enabled to use \"fde-registry\".");
}

pub fn get_finder() -> &'static Registry {
    &Registry(())
}

impl super::FDEFinder for Registry {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        unwinding_debugln!("Registry::find_fde: searching for PC 0x{:x}", pc);
        unsafe {
            let guard = lock_global_state();
            let mut cur = guard.object;
            let mut object_count = 0;

            while !cur.is_null() {
                object_count += 1;
                unwinding_debugln!("Registry::find_fde: checking object {} at {:p}", object_count, cur);
                let bases = BaseAddresses::default()
                    .set_text((*cur).tbase as _)
                    .set_got((*cur).dbase as _);
                match (*cur).table {
                    Table::Single(addr) => {
                        unwinding_debugln!("Registry::find_fde: checking single table at {:p}", addr);
                        let eh_frame = EhFrame::new(get_unlimited_slice(addr as _), NativeEndian);
                        let bases = bases.clone().set_eh_frame(addr as usize as _);
                        if let Ok(fde) =
                            eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset)
                        {
                            unwinding_debugln!("Registry::find_fde: found FDE in single table");
                            return Some(FDESearchResult {
                                fde,
                                bases,
                                eh_frame,
                            });
                        } else {
                            unwinding_debugln!("Registry::find_fde: no FDE found in single table");
                        }
                    }
                    Table::Multiple(mut addrs) => {
                        unwinding_debugln!("Registry::find_fde: checking multiple table starting at {:p}", addrs);
                        let mut addr = *addrs;
                        let mut table_index = 0;
                        while !addr.is_null() {
                            table_index += 1;
                            unwinding_debugln!("Registry::find_fde: checking table entry {} at {:p}", table_index, addr);
                            let eh_frame =
                                EhFrame::new(get_unlimited_slice(addr as _), NativeEndian);
                            let bases = bases.clone().set_eh_frame(addr as usize as _);
                            if let Ok(fde) =
                                eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset)
                            {
                                unwinding_debugln!("Registry::find_fde: found FDE in multiple table entry {}", table_index);
                                return Some(FDESearchResult {
                                    fde,
                                    bases,
                                    eh_frame,
                                });
                            } else {
                                unwinding_debugln!("Registry::find_fde: no FDE found in multiple table entry {}", table_index);
                            }

                            addrs = addrs.add(1);
                            addr = *addrs;
                        }
                    }
                }

                cur = (*cur).next;
            }
            
            unwinding_debugln!("Registry::find_fde: checked {} objects, no FDE found", object_count);
        }

        None
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __register_frame_info_bases(
    begin: *const c_void,
    ob: *mut Object,
    tbase: *const c_void,
    dbase: *const c_void,
) {
    unwinding_debugln!("__register_frame_info_bases: registering frame at {:p}", begin);
    if begin.is_null() {
        unwinding_debugln!("__register_frame_info_bases: begin is null, skipping");
        return;
    }

    unsafe {
        ob.write(Object {
            next: core::ptr::null_mut(),
            tbase: tbase as _,
            dbase: dbase as _,
            table: Table::Single(begin),
        });

        let mut guard = lock_global_state();
        (*ob).next = guard.object;
        guard.object = ob;
        unwinding_debugln!("__register_frame_info_bases: frame registered successfully");
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __register_frame_info(begin: *const c_void, ob: *mut Object) {
    unsafe { __register_frame_info_bases(begin, ob, core::ptr::null_mut(), core::ptr::null_mut()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __register_frame(begin: *const c_void) {
    if begin.is_null() {
        return;
    }

    let storage = Box::into_raw(Box::new(MaybeUninit::<Object>::uninit())) as *mut Object;
    unsafe { __register_frame_info(begin, storage) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __register_frame_info_table_bases(
    begin: *const c_void,
    ob: *mut Object,
    tbase: *const c_void,
    dbase: *const c_void,
) {
    unwinding_debugln!("__register_frame_info_table_bases: registering frame table at {:p}", begin);
    unsafe {
        ob.write(Object {
            next: core::ptr::null_mut(),
            tbase: tbase as _,
            dbase: dbase as _,
            table: Table::Multiple(begin as _),
        });

        let mut guard = lock_global_state();
        (*ob).next = guard.object;
        guard.object = ob;
        unwinding_debugln!("__register_frame_info_table_bases: frame table registered successfully");
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __register_frame_info_table(begin: *const c_void, ob: *mut Object) {
    unsafe {
        __register_frame_info_table_bases(begin, ob, core::ptr::null_mut(), core::ptr::null_mut())
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __register_frame_table(begin: *const c_void) {
    if begin.is_null() {
        return;
    }

    let storage = Box::into_raw(Box::new(MaybeUninit::<Object>::uninit())) as *mut Object;
    unsafe { __register_frame_info_table(begin, storage) }
}

#[unsafe(no_mangle)]
extern "C" fn __deregister_frame_info_bases(begin: *const c_void) -> *mut Object {
    if begin.is_null() {
        return core::ptr::null_mut();
    }

    let mut guard = unsafe { lock_global_state() };
    unsafe {
        let mut prev = &mut guard.object;
        let mut cur = *prev;

        while !cur.is_null() {
            let found = match (*cur).table {
                Table::Single(addr) => addr == begin,
                _ => false,
            };
            if found {
                *prev = (*cur).next;
                return cur;
            }
            prev = &mut (*cur).next;
            cur = *prev;
        }
    }

    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
extern "C" fn __deregister_frame_info(begin: *const c_void) -> *mut Object {
    __deregister_frame_info_bases(begin)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __deregister_frame(begin: *const c_void) {
    if begin.is_null() {
        return;
    }
    let storage = __deregister_frame_info(begin);
    drop(unsafe { Box::from_raw(storage as *mut MaybeUninit<Object>) })
}
