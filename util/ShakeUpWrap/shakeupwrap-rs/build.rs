use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // XKCP repository root (this crate lives in util/ShakeUpWrap/shakeupwrap-rs).
    let xkcp_root = std::env::var("XKCP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("../../..").canonicalize().unwrap());

    let target = std::env::var("XKCP_TARGET").unwrap_or_else(|_| "x86-64".to_string());
    let lib_dir = xkcp_root.join("bin").join(&target);
    let header_dir = lib_dir.join("libXKCP.a.headers");

    if !lib_dir.join("libXKCP.a").exists() {
        panic!(
            "libXKCP.a not found at {:?}. Build it first:\n  make {}/libXKCP.a",
            lib_dir.join("libXKCP.a"),
            target
        );
    }

    // Compile the C shim against the installed XKCP headers.
    cc::Build::new()
        .file("c_shim/suw_ffi.c")
        .include(&header_dir)
        .opt_level(3)
        .compile("suw_ffi");

    // Link the prebuilt XKCP static library.
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=XKCP");

    println!("cargo:rerun-if-changed=c_shim/suw_ffi.c");
    println!("cargo:rerun-if-env-changed=XKCP_DIR");
    println!("cargo:rerun-if-env-changed=XKCP_TARGET");
}
