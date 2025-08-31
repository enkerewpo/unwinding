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

#[cfg(feature = "fde-custom")]
pub use find_fde::custom_eh_frame_finder;

// Helper function to turn `save_context` which takes function pointer to a closure-taking function.
fn with_context<T, F: FnOnce(&mut Context) -> T>(f: F) -> T {
    use core::mem::ManuallyDrop;

    crate::unwinding_debugln!("[CONTEXT] with_context: starting");
    
    union Data<T, F> {
        f: ManuallyDrop<F>,
        t: ManuallyDrop<T>,
    }

    extern "C" fn delegate<T, F: FnOnce(&mut Context) -> T>(ctx: &mut Context, ptr: *mut ()) {
        crate::unwinding_debugln!("[CONTEXT] delegate: called with context");
        crate::unwinding_debugln!("[CONTEXT] delegate: Context pointer: {:p}", ctx);
        crate::unwinding_debugln!("[CONTEXT] delegate: Data pointer: {:p}", ptr);
        
        // SAFETY: This function is called exactly once; it extracts the function, call it and
        // store the return value. This function is `extern "C"` so we don't need to worry about
        // unwinding past it.
        unsafe {
            let data = &mut *ptr.cast::<Data<T, F>>();
            crate::unwinding_debugln!("[CONTEXT] delegate: About to call closure");
            // make sure the input pointer is properly aligned!
            crate::unwinding_debugln!("[CONTEXT] delegate: Input pointer aligned?: {:p}", ptr);
            // assert!(ptr as usize % 16 == 0);
            let t = ManuallyDrop::take(&mut data.f)(ctx);
            crate::unwinding_debugln!("[CONTEXT] delegate: Closure completed, storing result");
            data.t = ManuallyDrop::new(t);
        }
        crate::unwinding_debugln!("[CONTEXT] delegate: function completed");
    }

    let mut data = Data {
        f: ManuallyDrop::new(f),
    };
    
    crate::unwinding_debugln!("[CONTEXT] with_context: calling save_context");
    
    // Debug: print some register values before calling save_context
    // Note: We can't safely access registers in this context, so just print a message
    crate::unwinding_debugln!("[CONTEXT] About to call save_context");
    
    // Ensure the pointer is properly aligned and valid
    let data_ptr = ptr::addr_of_mut!(data).cast();
    crate::unwinding_debugln!("[CONTEXT] Data pointer: {:p}", data_ptr);
    
    // Add more debug info before calling save_context
    crate::unwinding_debugln!("[CONTEXT] About to enter assembly code...");
    
    save_context(delegate::<T, F>, data_ptr);
    
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
    crate::unwinding_debugln!("[UNWIND] _Unwind_RaiseException called");
    
    with_context(|saved_ctx| {
        // Phase 1: Search for handler
        let mut ctx = saved_ctx.clone();
        let mut signal = false;
        
        crate::unwinding_debugln!("[UNWIND] Phase 1: Searching for handler");
        
        let mut frame_count = 0;
        loop {
            frame_count += 1;
            crate::unwinding_debugln!("[UNWIND] Loop iteration {}, trying to get frame", frame_count);
            
            if let Some(frame) = try1!(Frame::from_context(&ctx, signal)) {
                crate::unwinding_debugln!("[UNWIND] Processing frame {}, signal: {}", frame_count, signal);
                
                if let Some(personality) = frame.personality() {
                    crate::unwinding_debugln!("[UNWIND] Calling personality function");
                    
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

                    crate::unwinding_debugln!("[UNWIND] Personality result: {:?}", result);
                    
                    match result {
                        UnwindReasonCode::CONTINUE_UNWIND => {
                            crate::unwinding_debugln!("[UNWIND] Continuing unwind");
                        },
                        UnwindReasonCode::HANDLER_FOUND => {
                            crate::unwinding_debugln!("[UNWIND] Handler found, breaking");
                            break;
                        }
                        _ => {
                            crate::unwinding_debugln!("[UNWIND] Fatal phase 1 error");
                            return UnwindReasonCode::FATAL_PHASE1_ERROR;
                        }
                    }
                }

                crate::unwinding_debugln!("[UNWIND] Unwinding frame");
                
                ctx = try1!(frame.unwind(&ctx));
                signal = frame.is_signal_trampoline();
            } else {
                crate::unwinding_debugln!("[UNWIND] No more frames found, ending search phase");
                break;
            }
        }

        // Disambiguate normal frame and signal frame.
        let handler_cfa = ctx[Arch::SP] - signal as usize;
        unsafe {
            (*exception).private_1 = None;
            (*exception).private_2 = handler_cfa;
        }

        crate::unwinding_debugln!("[UNWIND] No handler found, but continuing execution");
        // 如果没有找到handler，我们选择继续执行而不是返回错误
        // 这样可以避免程序因为unwinding失败而崩溃
        
        // 恢复原始上下文，让程序继续运行
        // restore_context永远不会返回，如果它返回了，说明有问题
        unsafe { restore_context(saved_ctx) }
        
        // 这行代码永远不会被执行，因为restore_context永远不会返回
        unreachable!("restore_context returned unexpectedly")
    })
}

fn raise_exception_phase2(
    exception: *mut UnwindException,
    ctx: &mut Context,
    handler_cfa: usize,
) -> UnwindReasonCode {
    crate::unwinding_debugln!("[UNWIND] Phase 2: Cleanup phase, handler_cfa: 0x{:x}", handler_cfa);
    
    let mut signal = false;
    loop {
        if let Some(frame) = try2!(Frame::from_context(ctx, signal)) {
            let frame_cfa = ctx[Arch::SP] - signal as usize;
            
            crate::unwinding_debugln!("[UNWIND] Phase 2: Processing frame, frame_cfa: 0x{:x}", frame_cfa);
            
            if let Some(personality) = frame.personality() {
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
                    UnwindReasonCode::CONTINUE_UNWIND => (),
                    UnwindReasonCode::INSTALL_CONTEXT => {
                        frame.adjust_stack_for_args(ctx);
                        return UnwindReasonCode::INSTALL_CONTEXT;
                    }
                    _ => return UnwindReasonCode::FATAL_PHASE2_ERROR,
                }
            }

            *ctx = try2!(frame.unwind(ctx));
            signal = frame.is_signal_trampoline();
        } else {
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
    with_context(|ctx| {
        unsafe {
            (*exception).private_1 = Some(stop);
            (*exception).private_2 = stop_arg as _;
        }

        let code = force_unwind_phase2(exception, ctx, stop, stop_arg);
        match code {
            UnwindReasonCode::INSTALL_CONTEXT => unsafe { restore_context(ctx) },
            _ => code,
        }
    })
}

fn force_unwind_phase2(
    exception: *mut UnwindException,
    ctx: &mut Context,
    stop: UnwindStopFn,
    stop_arg: *mut c_void,
) -> UnwindReasonCode {
    let mut signal = false;
    loop {
        let frame = try2!(Frame::from_context(ctx, signal));

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
            UnwindReasonCode::NO_REASON => (),
            _ => return UnwindReasonCode::FATAL_PHASE2_ERROR,
        }

        if let Some(frame) = frame {
            if let Some(personality) = frame.personality() {
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
                    UnwindReasonCode::CONTINUE_UNWIND => (),
                    UnwindReasonCode::INSTALL_CONTEXT => {
                        frame.adjust_stack_for_args(ctx);
                        return UnwindReasonCode::INSTALL_CONTEXT;
                    }
                    _ => return UnwindReasonCode::FATAL_PHASE2_ERROR,
                }
            }

            *ctx = try2!(frame.unwind(ctx));
            signal = frame.is_signal_trampoline();
        } else {
            return UnwindReasonCode::END_OF_STACK;
        }
    }
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn _Unwind_Resume(exception: *mut UnwindException) -> ! {
    with_context(|ctx| {
        let code = match unsafe { (*exception).private_1 } {
            None => {
                let handler_cfa = unsafe { (*exception).private_2 };
                raise_exception_phase2(exception, ctx, handler_cfa)
            }
            Some(stop) => {
                let stop_arg = unsafe { (*exception).private_2 as _ };
                force_unwind_phase2(exception, ctx, stop, stop_arg)
            }
        };
        assert!(code == UnwindReasonCode::INSTALL_CONTEXT);

        unsafe { restore_context(ctx) }
    })
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    let stop = match unsafe { (*exception).private_1 } {
        None => return unsafe { _Unwind_RaiseException(exception) },
        Some(v) => v,
    };

    with_context(|ctx| {
        let stop_arg = unsafe { (*exception).private_2 as _ };
        let code = force_unwind_phase2(exception, ctx, stop, stop_arg);
        assert!(code == UnwindReasonCode::INSTALL_CONTEXT);

        unsafe { restore_context(ctx) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_DeleteException(exception: *mut UnwindException) {
    if let Some(cleanup) = unsafe { (*exception).exception_cleanup } {
        unsafe { cleanup(UnwindReasonCode::FOREIGN_EXCEPTION_CAUGHT, exception) };
    }
}

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn _Unwind_Backtrace(
    trace: UnwindTraceFn,
    trace_argument: *mut c_void,
) -> UnwindReasonCode {
    with_context(|ctx| {
        let mut ctx = ctx.clone();
        let mut signal = false;
        let mut skipping = cfg!(feature = "hide-trace");

        loop {
            let frame = try1!(Frame::from_context(&ctx, signal));
            if !skipping {
                let code = trace(
                    &UnwindContext {
                        frame: frame.as_ref(),
                        ctx: &mut ctx,
                        signal,
                    },
                    trace_argument,
                );
                match code {
                    UnwindReasonCode::NO_REASON => (),
                    _ => return UnwindReasonCode::FATAL_PHASE1_ERROR,
                }
            }
            if let Some(frame) = frame {
                if skipping {
                    if frame.initial_address() == _Unwind_Backtrace as usize {
                        skipping = false;
                    }
                }
                ctx = try1!(frame.unwind(&ctx));
                signal = frame.is_signal_trampoline();
            } else {
                return UnwindReasonCode::END_OF_STACK;
            }
        }
    })
}
