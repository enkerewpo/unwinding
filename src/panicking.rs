use core::mem::ManuallyDrop;

use crate::abi::*;

pub unsafe trait Exception {
    const CLASS: [u8; 8];

    fn wrap(this: Self) -> *mut UnwindException;
    unsafe fn unwrap(ex: *mut UnwindException) -> Self;
}

pub fn begin_panic<E: Exception>(exception: E) -> UnwindReasonCode {
    crate::unwinding_debugln!("[PANICKING] begin_panic called");
    
    unsafe extern "C" fn exception_cleanup<E: Exception>(
        _unwind_code: UnwindReasonCode,
        exception: *mut UnwindException,
    ) {
        crate::unwinding_debugln!("[PANICKING] exception_cleanup called with code: {:?}", _unwind_code);
        unsafe { E::unwrap(exception) };
    }

    let ex = E::wrap(exception);
    crate::unwinding_debugln!("[PANICKING] Exception wrapped, calling _Unwind_RaiseException");
    
    unsafe {
        (*ex).exception_class = u64::from_ne_bytes(E::CLASS);
        (*ex).exception_cleanup = Some(exception_cleanup::<E>);
        let result = _Unwind_RaiseException(ex);
        crate::unwinding_debugln!("[PANICKING] _Unwind_RaiseException returned: {:?}", result);
        result
    }
}

pub fn catch_unwind<E: Exception, R, F: FnOnce() -> R>(f: F) -> Result<R, Option<E>> {
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
        crate::unwinding_debugln!("[PANICKING] catch_unwind: calling core::intrinsics::catch_unwind");
        let result = core::intrinsics::catch_unwind(do_call::<F, R>, data_ptr, do_catch::<E>);
        crate::unwinding_debugln!("[PANICKING] catch_unwind: intrinsics returned: {}", result);
        
        return if result == 0 {
            crate::unwinding_debugln!("[PANICKING] catch_unwind: function completed successfully");
            Ok(ManuallyDrop::into_inner(data.r))
        } else {
            crate::unwinding_debugln!("[PANICKING] catch_unwind: function panicked");
            Err(ManuallyDrop::into_inner(data.p))
        };
    }

    #[inline]
    fn do_call<F: FnOnce() -> R, R>(data: *mut u8) {
        unsafe {
            let data = &mut *(data as *mut Data<F, R, ()>);
            let f = ManuallyDrop::take(&mut data.f);
            data.r = ManuallyDrop::new(f());
        }
    }

    #[cold]
    fn do_catch<E: Exception>(data: *mut u8, exception: *mut u8) {
        crate::unwinding_debugln!("[PANICKING] do_catch: exception caught");
        unsafe {
            let data = &mut *(data as *mut ManuallyDrop<Option<E>>);
            let exception = exception as *mut UnwindException;
            let exception_class = (*exception).exception_class;
            crate::unwinding_debugln!("[PANICKING] do_catch: exception class: {:?}", exception_class);
            
            if exception_class != u64::from_ne_bytes(E::CLASS) {
                crate::unwinding_debugln!("[PANICKING] do_catch: foreign exception, deleting");
                _Unwind_DeleteException(exception);
                *data = ManuallyDrop::new(None);
                return;
            }
            crate::unwinding_debugln!("[PANICKING] do_catch: unwrapping exception");
            *data = ManuallyDrop::new(Some(E::unwrap(exception)));
        }
    }
}
