use core::mem::ManuallyDrop;

use crate::abi::*;
use crate::baremetal_debug::unwinding_debugln;

pub unsafe trait Exception {
    const CLASS: [u8; 8];

    fn wrap(this: Self) -> *mut UnwindException;
    unsafe fn unwrap(ex: *mut UnwindException) -> Self;
}

pub fn begin_panic<E: Exception>(exception: E) -> UnwindReasonCode {
    unwinding_debugln!("begin_panic: starting panic");
    unsafe extern "C" fn exception_cleanup<E: Exception>(
        _unwind_code: UnwindReasonCode,
        exception: *mut UnwindException,
    ) {
        unwinding_debugln!("exception_cleanup: cleaning up exception");
        unsafe { E::unwrap(exception) };
    }

    let ex = E::wrap(exception);
    unsafe {
        (*ex).exception_class = u64::from_ne_bytes(E::CLASS);
        (*ex).exception_cleanup = Some(exception_cleanup::<E>);
        unwinding_debugln!("begin_panic: calling _Unwind_RaiseException");
        _Unwind_RaiseException(ex)
    }
}

pub fn catch_unwind<E: Exception, R, F: FnOnce() -> R>(f: F) -> Result<R, Option<E>> {
    unwinding_debugln!("catch_unwind: setting up catch_unwind");
    #[repr(C)]
    union Data<F, R, E> {
        f: ManuallyDrop<F>,
        r: ManuallyDrop<R>,
        p: ManuallyDrop<Option<E>>,
    }

    let mut data = Data {
        f: ManuallyDrop::new(f),
    };

    let data_ptr = &mut data as *mut _ as *mut u8;
    unsafe {
        unwinding_debugln!("catch_unwind: calling core::intrinsics::catch_unwind");
        return if core::intrinsics::catch_unwind(do_call::<F, R>, data_ptr, do_catch::<E>) == 0 {
            unwinding_debugln!("catch_unwind: function completed successfully");
            Ok(ManuallyDrop::into_inner(data.r))
        } else {
            unwinding_debugln!("catch_unwind: function panicked");
            Err(ManuallyDrop::into_inner(data.p))
        };
    }

    #[inline]
    fn do_call<F: FnOnce() -> R, R>(data: *mut u8) {
        unwinding_debugln!("do_call: executing function");
        unsafe {
            let data = &mut *(data as *mut Data<F, R, ()>);
            let f = ManuallyDrop::take(&mut data.f);
            data.r = ManuallyDrop::new(f());
        }
    }

    #[cold]
    fn do_catch<E: Exception>(data: *mut u8, exception: *mut u8) {
        unwinding_debugln!("do_catch: catching exception");
        unsafe {
            let data = &mut *(data as *mut ManuallyDrop<Option<E>>);
            let exception = exception as *mut UnwindException;
            if (*exception).exception_class != u64::from_ne_bytes(E::CLASS) {
                unwinding_debugln!("do_catch: exception class mismatch, deleting foreign exception");
                _Unwind_DeleteException(exception);
                *data = ManuallyDrop::new(None);
                return;
            }
            unwinding_debugln!("do_catch: exception class matches, unwrapping");
            *data = ManuallyDrop::new(Some(E::unwrap(exception)));
        }
    }
}