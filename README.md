# cs594-sp25-ebpf


Final project of CS 594 taught by Prof. Wang at UIC 

Contributor: Dimitar Gjorgievski, Manh Nguyen

EBPF network filtering

# xdp-filter

Run command:
```
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' (this assumes eth0 interface)
```
or pass in the interface (wlp2s0) as:
```
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- \
  --iface wlp2s0
```

Dynamically add a website:

```
RUST_LOG=info cargo run -p xdp-filter-dynamic --config 'target."cfg(all())".runner="sudo -E"' -- netflix.com
```

Dynamically remove a website:

```
RUST_LOG=info cargo run -p xdp-filter-dynamic --config 'target."cfg(all())".runner="sudo -E"' -- netflix.com --remove
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package xdp-filter --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/xdp-filter` can be
copied to a Linux server or VM and run there.
