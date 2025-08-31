#![cfg(feature = "baremetal-debug")]

use core::fmt::{self, Write};
use ns16550a::*;
use spin::Mutex;

// Global UART instance for baremetal debug output
static UART: Mutex<Uart> = Mutex::new(Uart::new(0x8000_0000_1fe0_01e0));
static INITIALIZED: Mutex<bool> = Mutex::new(false);

/// Initialize the UART if not already initialized
fn ensure_uart_initialized() {
    // Use a simple approach to avoid deadlock
    static mut INIT_DONE: bool = false;
    
    unsafe {
        if !INIT_DONE {
            UART.lock().init(
                WordLength::EIGHT,
                StopBits::ONE,
                ParityBit::DISABLE,
                ParitySelect::EVEN,
                StickParity::DISABLE,
                Break::DISABLE,
                DMAMode::MODE0,
                Divisor::BAUD115200,
            );
            INIT_DONE = true;
        }
    }
}

struct BaremetalDebugWriter;

impl Write for BaremetalDebugWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        ensure_uart_initialized();
        
        // Try to get UART lock, but don't block if it's already locked
        if let Some(mut uart) = UART.try_lock() {
            for c in s.chars() {
                if c == '\n' {
                    let _ = uart.write_char('\r');
                }
                let _ = uart.write_char(c);
            }
        }
        Ok(())
    }
}

/// Internal debug print function used by unwinding library
#[doc(hidden)]
pub fn _baremetal_debug_print(args: core::fmt::Arguments) {
    // Add a simple test output first
    if let Some(mut uart) = UART.try_lock() {
        let _ = uart.write_str("DBG: ");
    }
    
    let _ = BaremetalDebugWriter.write_fmt(args);
}

/// Internal debug println function used by unwinding library
#[doc(hidden)]
pub fn _baremetal_debug_println(args: core::fmt::Arguments) {
    let _ = BaremetalDebugWriter.write_fmt(args);
    let _ = BaremetalDebugWriter.write_str("\n");
}

/// Debug print macro for unwinding library internal use
#[macro_export]
macro_rules! unwinding_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "baremetal-debug")]
        $crate::baremetal_debug::_baremetal_debug_print(format_args!($($arg)*));
    };
}

/// Debug println macro for unwinding library internal use
#[macro_export]
macro_rules! unwinding_debugln {
    () => {
        #[cfg(feature = "baremetal-debug")]
        $crate::baremetal_debug::_baremetal_debug_println(format_args!("[{}:{}]", file!(), line!()));
    };
    ($fmt:expr) => {
        #[cfg(feature = "baremetal-debug")]
        $crate::baremetal_debug::_baremetal_debug_println(format_args!("[{}:{}] {}", file!(), line!(), format_args!($fmt)));
    };
    ($fmt:expr, $($arg:tt)*) => {
        #[cfg(feature = "baremetal-debug")]
        $crate::baremetal_debug::_baremetal_debug_println(format_args!("[{}:{}] {}", file!(), line!(), format_args!($fmt, $($arg)*)));
    };
}

// Re-export macros at module level for internal use
pub use crate::unwinding_debug;
pub use crate::unwinding_debugln;
