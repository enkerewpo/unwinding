#!/bin/bash
set -e

# pass arch in as argument
ARCH_ARG=$1
# pass DEBUG=1 in env
if [ "$DEBUG" == "1" ]; then
    DEBUG_ENABLED=1
else
    DEBUG_ENABLED=0
fi

if [ "$GDB" == "1" ]; then
    GDB_ENABLED=1
else
    GDB_ENABLED=0
fi

if [ "$ARCH_ARG" == "loongarch64" ]; then
    # loongarch64 variables
    ARCH=loongarch64
    RUST_TARGET=loongarch64-unknown-linux-gnu
    CROSS_COMPILE=loongarch64-unknown-linux-gnu-
    OBJDUMP=loongarch64-unknown-linux-gnu-objdump
    READELF=loongarch64-unknown-linux-gnu-readelf
    GDB=loongarch64-unknown-linux-gnu-gdb
    CARGO_TARGET=CARGO_TARGET_LOONGARCH64_UNKNOWN_LINUX_GNU_LINKER
    QEMU_USER=qemu-loongarch64
elif [ "$ARCH_ARG" == "aarch64" ]; then
    # aarch64 variables
    ARCH=aarch64
    RUST_TARGET=aarch64-unknown-linux-gnu
    CROSS_COMPILE=aarch64-unknown-linux-gnu-
    OBJDUMP=aarch64-unknown-linux-gnu-objdump
    READELF=aarch64-unknown-linux-gnu-readelf
    GDB=aarch64-unknown-linux-gnu-gdb
    CARGO_TARGET=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
    QEMU_USER=qemu-aarch64
elif [ "$ARCH_ARG" == "riscv64" ]; then
    # riscv64 variables
    ARCH=riscv64
    RUST_TARGET=riscv64-unknown-linux-gnu
    CROSS_COMPILE=riscv64-unknown-linux-gnu-
    OBJDUMP=riscv64-unknown-linux-gnu-objdump
    READELF=riscv64-unknown-linux-gnu-readelf
    GDB=riscv64-unknown-linux-gnu-gdb
    CARGO_TARGET=CARGO_TARGET_RISCV64_UNKNOWN_LINUX_GNU_LINKER
    QEMU_USER=qemu-riscv64
else
    if [ -z "$ARCH_ARG" ]; then
        # we use host arch and without using any cross prefix
        ARCH=$(uname -m)
        RUST_TARGET=$ARCH-unknown-linux-gnu
        CROSS_COMPILE=
        OBJDUMP=objdump
        READELF=readelf
        GDB=gdb
        CARGO_TARGET=
        QEMU_USER=qemu-$ARCH
    else
        echo "Invalid architecture: $ARCH_ARG"
        exit 1
    fi
fi

echo "Building for $ARCH, $RUST_TARGET, $CROSS_COMPILE, $CARGO_TARGET, $QEMU_USER"

CC=gcc

if [ -n "$CARGO_TARGET" ]; then
    export $CARGO_TARGET=$CROSS_COMPILE$CC
fi
cargo build --target $RUST_TARGET

# get program name from current directory name
PROGRAM_NAME=$(basename $(pwd))
TARGET_FILE=../../target/$RUST_TARGET/debug/$PROGRAM_NAME
file $TARGET_FILE
# disam to TARGET_FILE.disasm
$OBJDUMP -d -S $TARGET_FILE > $TARGET_FILE.disasm
$READELF -a $TARGET_FILE > $TARGET_FILE.readelf
# dump eh_frame and eh_frame_hdr
$READELF -wf $TARGET_FILE > $TARGET_FILE.eh_frame_hdr

if [ "$DEBUG_ENABLED" == 1 ]; then
    QEMU_USER_FLAGS="-d in_asm,cpu"
else
    QEMU_USER_FLAGS=""
fi

QEMU_OUTPUT_LOG=$TARGET_FILE.qemu.log

if [ "$DEBUG_ENABLED" == 1 ]; then
    $QEMU_USER $QEMU_USER_FLAGS $TARGET_FILE > $QEMU_OUTPUT_LOG 2>&1
else
    if [ "$GDB_ENABLED" == 1 ]; then
        # Use cross gdb for breakpoint debugging
        echo "Starting QEMU with GDB server on port 1234..."
        # Start QEMU in background with GDB server
        $QEMU_USER -g 1234 $QEMU_USER_FLAGS $TARGET_FILE &
        QEMU_PID=$!
        
        # Wait a moment for QEMU to start
        sleep 1
        
        echo "Starting GDB debugging session..."
        $GDB -ex "set architecture $ARCH" \
             -ex "target remote localhost:1234" \
             -ex "file $TARGET_FILE" \
             -ex "break main" \
             -ex "continue" \
             $TARGET_FILE
        
        # Clean up QEMU process
        kill $QEMU_PID 2>/dev/null || true
    else
        $QEMU_USER $QEMU_USER_FLAGS $TARGET_FILE
    fi
fi

# b _ZN9unwinding8unwinder12with_context17h8fe48f9b3ecb8f3dE
# b *0x7fbeec69bd90 + 84
# b src/unwinder/mod.rs:47


# https://github.com/rust-lang/rust/blob/master/compiler/rustc_target/src/target_features.rs