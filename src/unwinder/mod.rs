mod arch;
mod find_fde;
mod frame;

use core::ffi::c_void;
use core::ptr;
use gimli::Register;

use crate::abi::*;
use crate::arch::*;
use crate::util::*;
use arch::*;
use find_fde::FDEFinder;
use frame::Frame;
use crate::baremetal_debug::unwinding_debugln;

#[cfg(feature = "fde-custom")]
pub use find_fde::custom_eh_frame_finder;

// Helper function to turn `save_context` which takes function pointer to a closure-taking function.
fn with_context<T, F: FnOnce(&mut Context) -> T>(f: F) -> T {
    use core::mem::ManuallyDrop;


    unwinding_debugln!("with_context: begin");
    union Data<T, F> {
        f: ManuallyDrop<F>,
        t: ManuallyDrop<T>,
    }

    extern "C" fn delegate<T, F: FnOnce(&mut Context) -> T>(ctx: &mut Context, ptr: *mut ()) {
        // SAFETY: This function is called exactly once; it extracts the function, call it and
        // store the return value. This function is `extern "C"` so we don't need to worry about
        // unwinding past it.
        unsafe {
            let data = &mut *ptr.cast::<Data<T, F>>();
            unwinding_debugln!("delegate: {} calling manually drop take", file!());
            let t = ManuallyDrop::take(&mut data.f)(ctx);
            data.t = ManuallyDrop::new(t);
        }
    }

    let mut data = Data {
        f: ManuallyDrop::new(f),
    };

    unwinding_debugln!("with_context: calling save_context");

    save_context(delegate::<T, F>, ptr::addr_of_mut!(data).cast());

    unwinding_debugln!("with_context: save_context returned");

    unsafe { ManuallyDrop::into_inner(data.t) }
}

#[repr(C)]
pub struct UnwindException {
    pub exception_class: u64,
    pub exception_cleanup: Option<UnwindExceptionCleanupFn>,
    private_1: Option<UnwindStopFn>,
    private_2: usize,
    private_unused: [usize; Arch::UNWIND_PRIVATE_DATA_SIZE - 2],
}

pub struct UnwindContext<'a> {
    frame: Option<&'a Frame>,
    ctx: &'a mut Context,
    signal: bool,
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetGR(unwind_ctx: &UnwindContext<'_>, index: c_int) -> usize {
    unwind_ctx.ctx[Register(index as u16)]
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetCFA(unwind_ctx: &UnwindContext<'_>) -> usize {
    unwind_ctx.ctx[Arch::SP]
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_SetGR(unwind_ctx: &mut UnwindContext<'_>, index: c_int, value: usize) {
    unwind_ctx.ctx[Register(index as u16)] = value;
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetIP(unwind_ctx: &UnwindContext<'_>) -> usize {
    unwind_ctx.ctx[Arch::RA]
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetIPInfo(
    unwind_ctx: &UnwindContext<'_>,
    ip_before_insn: &mut c_int,
) -> usize {
    *ip_before_insn = unwind_ctx.signal as _;
    unwind_ctx.ctx[Arch::RA]
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_SetIP(unwind_ctx: &mut UnwindContext<'_>, value: usize) {
    unwind_ctx.ctx[Arch::RA] = value;
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetLanguageSpecificData(unwind_ctx: &UnwindContext<'_>) -> *mut c_void {
    unwind_ctx
        .frame
        .map(|f| f.lsda() as *mut c_void)
        .unwrap_or(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetRegionStart(unwind_ctx: &UnwindContext<'_>) -> usize {
    unwind_ctx.frame.map(|f| f.initial_address()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetTextRelBase(unwind_ctx: &UnwindContext<'_>) -> usize {
    unwind_ctx
        .frame
        .map(|f| f.bases().eh_frame.text.unwrap() as _)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_GetDataRelBase(unwind_ctx: &UnwindContext<'_>) -> usize {
    unwind_ctx
        .frame
        .map(|f| f.bases().eh_frame.data.unwrap() as _)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void {
    find_fde::get_finder()
        .find_fde(pc as usize - 1)
        .map(|r| r.fde.initial_address() as usize as _)
        .unwrap_or(ptr::null_mut())
}

macro_rules! try1 {
    ($e: expr) => {{
        match $e {
            Ok(v) => v,
            Err(_) => return UnwindReasonCode::FATAL_PHASE1_ERROR,
        }
    }};
}

macro_rules! try2 {
    ($e: expr) => {{
        match $e {
            Ok(v) => v,
            Err(_) => return UnwindReasonCode::FATAL_PHASE2_ERROR,
        }
    }};
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn _Unwind_RaiseException(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    unwinding_debugln!("_Unwind_RaiseException: starting phase 1 search");
    with_context(|saved_ctx| {
        // Phase 1: Search for handler
        let mut ctx = saved_ctx.clone();
        let mut signal = false;
        loop {
            if let Some(frame) = try1!(Frame::from_context(&ctx, signal)) {
                unwinding_debugln!("_Unwind_RaiseException: found frame");
                if let Some(personality) = frame.personality() {
                    unwinding_debugln!("_Unwind_RaiseException: calling personality function");
                    let result = unsafe {
                        personality(
                            1,
                            UnwindAction::SEARCH_PHASE,
                            (*exception).exception_class,
                            exception,
                            &mut UnwindContext {
                                frame: Some(&frame),
                                ctx: &mut ctx,
                                signal,
                            },
                        )
                    };

                    match result {
                        UnwindReasonCode::CONTINUE_UNWIND => {
                            unwinding_debugln!("_Unwind_RaiseException: personality returned CONTINUE_UNWIND");
                        },
                        UnwindReasonCode::HANDLER_FOUND => {
                            unwinding_debugln!("_Unwind_RaiseException: handler found, breaking search");
                            break;
                        }
                        _ => {
                            unwinding_debugln!("_Unwind_RaiseException: personality returned error: {:?}", result);
                            return UnwindReasonCode::FATAL_PHASE1_ERROR;
                        }
                    }
                } else {
                    unwinding_debugln!("_Unwind_RaiseException: no personality function for frame");
                }

                unwinding_debugln!("_Unwind_RaiseException: unwinding frame");
                ctx = try1!(frame.unwind(&ctx));
                signal = frame.is_signal_trampoline();
                unwinding_debugln!("_Unwind_RaiseException: frame unwound, signal: {}", signal);
            } else {
                unwinding_debugln!("_Unwind_RaiseException: no more frames, end of stack");
                return UnwindReasonCode::END_OF_STACK;
            }
        }

        // Disambiguate normal frame and signal frame.
        let handler_cfa = ctx[Arch::SP] - signal as usize;
        unwinding_debugln!("_Unwind_RaiseException: handler_cfa = 0x{:x}, signal = {}", handler_cfa, signal);
        unsafe {
            (*exception).private_1 = None;
            (*exception).private_2 = handler_cfa;
        }

        unwinding_debugln!("_Unwind_RaiseException: starting phase 2");
        let code = raise_exception_phase2(exception, saved_ctx, handler_cfa);
        match code {
            UnwindReasonCode::INSTALL_CONTEXT => {
                unwinding_debugln!("_Unwind_RaiseException: installing context");
                unsafe { restore_context(saved_ctx) }
            },
            _ => {
                unwinding_debugln!("_Unwind_RaiseException: phase 2 returned: {:?}", code);
                code
            }
        }
    })
}

fn raise_exception_phase2(
    exception: *mut UnwindException,
    ctx: &mut Context,
    handler_cfa: usize,
) -> UnwindReasonCode {
    unwinding_debugln!("raise_exception_phase2: starting cleanup phase");
    let mut signal = false;
    loop {
        if let Some(frame) = try2!(Frame::from_context(ctx, signal)) {
            let frame_cfa = ctx[Arch::SP] - signal as usize;
            unwinding_debugln!("raise_exception_phase2: processing frame, frame_cfa = 0x{:x}", frame_cfa);
            if let Some(personality) = frame.personality() {
                unwinding_debugln!("raise_exception_phase2: calling personality function");
                let code = unsafe {
                    personality(
                        1,
                        UnwindAction::CLEANUP_PHASE
                            | if frame_cfa == handler_cfa {
                                UnwindAction::HANDLER_FRAME
                            } else {
                                UnwindAction::empty()
                            },
                        (*exception).exception_class,
                        exception,
                        &mut UnwindContext {
                            frame: Some(&frame),
                            ctx,
                            signal,
                        },
                    )
                };

                match code {
                    UnwindReasonCode::CONTINUE_UNWIND => {
                        unwinding_debugln!("raise_exception_phase2: personality returned CONTINUE_UNWIND");
                    },
                    UnwindReasonCode::INSTALL_CONTEXT => {
                        unwinding_debugln!("raise_exception_phase2: installing context for frame");
                        frame.adjust_stack_for_args(ctx);
                        return UnwindReasonCode::INSTALL_CONTEXT;
                    }
                    _ => {
                        unwinding_debugln!("raise_exception_phase2: personality returned error: {:?}", code);
                        return UnwindReasonCode::FATAL_PHASE2_ERROR;
                    }
                }
            } else {
                unwinding_debugln!("raise_exception_phase2: no personality function for frame");
            }

            unwinding_debugln!("raise_exception_phase2: unwinding frame");
            *ctx = try2!(frame.unwind(ctx));
            signal = frame.is_signal_trampoline();
            unwinding_debugln!("raise_exception_phase2: frame unwound, signal: {}", signal);
        } else {
            unwinding_debugln!("raise_exception_phase2: no more frames, fatal error");
            return UnwindReasonCode::FATAL_PHASE2_ERROR;
        }
    }
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn _Unwind_ForcedUnwind(
    exception: *mut UnwindException,
    stop: UnwindStopFn,
    stop_arg: *mut c_void,
) -> UnwindReasonCode {
    unwinding_debugln!("_Unwind_ForcedUnwind: starting forced unwind");
    with_context(|ctx| {
        unsafe {
            (*exception).private_1 = Some(stop);
            (*exception).private_2 = stop_arg as _;
        }

        let code = force_unwind_phase2(exception, ctx, stop, stop_arg);
        match code {
            UnwindReasonCode::INSTALL_CONTEXT => {
                unwinding_debugln!("_Unwind_ForcedUnwind: installing context");
                unsafe { restore_context(ctx) }
            },
            _ => {
                unwinding_debugln!("_Unwind_ForcedUnwind: returned: {:?}", code);
                code
            }
        }
    })
}

fn force_unwind_phase2(
    exception: *mut UnwindException,
    ctx: &mut Context,
    stop: UnwindStopFn,
    stop_arg: *mut c_void,
) -> UnwindReasonCode {
    unwinding_debugln!("force_unwind_phase2: starting forced unwind phase 2");
    let mut signal = false;
    loop {
        let frame = try2!(Frame::from_context(ctx, signal));
        unwinding_debugln!("force_unwind_phase2: processing frame at {:p}", frame.as_ref().map(|f| f as *const _).unwrap_or(ptr::null()));

        let code = unsafe {
            stop(
                1,
                UnwindAction::FORCE_UNWIND
                    | UnwindAction::END_OF_STACK
                    | if frame.is_none() {
                        UnwindAction::END_OF_STACK
                    } else {
                        UnwindAction::empty()
                    },
                (*exception).exception_class,
                exception,
                &mut UnwindContext {
                    frame: frame.as_ref(),
                    ctx,
                    signal,
                },
                stop_arg,
            )
        };
        match code {
            UnwindReasonCode::NO_REASON => {
                unwinding_debugln!("force_unwind_phase2: stop function returned NO_REASON");
            },
            _ => {
                unwinding_debugln!("force_unwind_phase2: stop function returned error: {:?}", code);
                return UnwindReasonCode::FATAL_PHASE2_ERROR;
            }
        }

        if let Some(frame) = frame {
            if let Some(personality) = frame.personality() {
                unwinding_debugln!("force_unwind_phase2: calling personality function");
                let code = unsafe {
                    personality(
                        1,
                        UnwindAction::FORCE_UNWIND | UnwindAction::CLEANUP_PHASE,
                        (*exception).exception_class,
                        exception,
                        &mut UnwindContext {
                            frame: Some(&frame),
                            ctx,
                            signal,
                        },
                    )
                };

                match code {
                    UnwindReasonCode::CONTINUE_UNWIND => {
                        unwinding_debugln!("force_unwind_phase2: personality returned CONTINUE_UNWIND");
                    },
                    UnwindReasonCode::INSTALL_CONTEXT => {
                        unwinding_debugln!("force_unwind_phase2: installing context");
                        frame.adjust_stack_for_args(ctx);
                        return UnwindReasonCode::INSTALL_CONTEXT;
                    }
                    _ => {
                        unwinding_debugln!("force_unwind_phase2: personality returned error: {:?}", code);
                        return UnwindReasonCode::FATAL_PHASE2_ERROR;
                    }
                }
            } else {
                unwinding_debugln!("force_unwind_phase2: no personality function for frame");
            }

            unwinding_debugln!("force_unwind_phase2: unwinding frame");
            *ctx = try2!(frame.unwind(ctx));
            signal = frame.is_signal_trampoline();
            unwinding_debugln!("force_unwind_phase2: frame unwound, signal: {}", signal);
        } else {
            unwinding_debugln!("force_unwind_phase2: no more frames, end of stack");
            return UnwindReasonCode::END_OF_STACK;
        }
    }
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn _Unwind_Resume(exception: *mut UnwindException) -> ! {
    unwinding_debugln!("_Unwind_Resume: resuming unwind");
    with_context(|ctx| {
        let code = match unsafe { (*exception).private_1 } {
            None => {
                unwinding_debugln!("_Unwind_Resume: resuming exception raise");
                let handler_cfa = unsafe { (*exception).private_2 };
                raise_exception_phase2(exception, ctx, handler_cfa)
            }
            Some(stop) => {
                unwinding_debugln!("_Unwind_Resume: resuming forced unwind");
                let stop_arg = unsafe { (*exception).private_2 as _ };
                force_unwind_phase2(exception, ctx, stop, stop_arg)
            }
        };
        assert!(code == UnwindReasonCode::INSTALL_CONTEXT);

        unwinding_debugln!("_Unwind_Resume: installing context");
        unsafe { restore_context(ctx) }
    })
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    unwinding_debugln!("_Unwind_Resume_or_Rethrow: checking exception type");
    let stop = match unsafe { (*exception).private_1 } {
        None => {
            unwinding_debugln!("_Unwind_Resume_or_Rethrow: rethrowing exception");
            return unsafe { _Unwind_RaiseException(exception) };
        },
        Some(v) => v,
    };

    unwinding_debugln!("_Unwind_Resume_or_Rethrow: resuming forced unwind");
    with_context(|ctx| {
        let stop_arg = unsafe { (*exception).private_2 as _ };
        let code = force_unwind_phase2(exception, ctx, stop, stop_arg);
        assert!(code == UnwindReasonCode::INSTALL_CONTEXT);

        unwinding_debugln!("_Unwind_Resume_or_Rethrow: installing context");
        unsafe { restore_context(ctx) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_DeleteException(exception: *mut UnwindException) {
    unwinding_debugln!("_Unwind_DeleteException: deleting exception");
    if let Some(cleanup) = unsafe { (*exception).exception_cleanup } {
        unwinding_debugln!("_Unwind_DeleteException: calling cleanup function");
        unsafe { cleanup(UnwindReasonCode::FOREIGN_EXCEPTION_CAUGHT, exception) };
    } else {
        unwinding_debugln!("_Unwind_DeleteException: no cleanup function");
    }
}

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn _Unwind_Backtrace(
    trace: UnwindTraceFn,
    trace_argument: *mut c_void,
) -> UnwindReasonCode {
    unwinding_debugln!("_Unwind_Backtrace: starting backtrace");
    with_context(|ctx| {
        let mut ctx = ctx.clone();
        let mut signal = false;
        let mut skipping = cfg!(feature = "hide-trace");

        loop {
            let frame = try1!(Frame::from_context(&ctx, signal));
            unwinding_debugln!("_Unwind_Backtrace: found frame at {:p}", frame.as_ref().map(|f| f as *const _).unwrap_or(ptr::null()));
            if !skipping {
                unwinding_debugln!("_Unwind_Backtrace: calling trace function");
                let code = trace(
                    &UnwindContext {
                        frame: frame.as_ref(),
                        ctx: &mut ctx,
                        signal,
                    },
                    trace_argument,
                );
                match code {
                    UnwindReasonCode::NO_REASON => {
                        unwinding_debugln!("_Unwind_Backtrace: trace function returned NO_REASON");
                    },
                    _ => {
                        unwinding_debugln!("_Unwind_Backtrace: trace function returned error: {:?}", code);
                        return UnwindReasonCode::FATAL_PHASE1_ERROR;
                    }
                }
            }
            if let Some(frame) = frame {
                if skipping {
                    if frame.initial_address() == _Unwind_Backtrace as usize {
                        unwinding_debugln!("_Unwind_Backtrace: stopped skipping frames");
                        skipping = false;
                    }
                }
                unwinding_debugln!("_Unwind_Backtrace: unwinding frame");
                ctx = try1!(frame.unwind(&ctx));
                signal = frame.is_signal_trampoline();
                unwinding_debugln!("_Unwind_Backtrace: frame unwound, signal: {}", signal);
            } else {
                unwinding_debugln!("_Unwind_Backtrace: no more frames, end of stack");
                return UnwindReasonCode::END_OF_STACK;
            }
        }
    })
}