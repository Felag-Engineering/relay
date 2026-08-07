/// Generates the prost message types this fuzz crate decodes, straight from
/// /proto — the single source of truth for the wire contract (ADR-0007).
///
/// Mirrors daemon/build.rs but uses prost-build directly instead of
/// tonic-build: the fuzz surface is pure message decoding, so no gRPC
/// client/server codegen is wanted. The vendored protoc keeps the build
/// hermetic (no system protoc required), same as the daemon.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // prost-build respects PROTOC when no system protoc is installed.
    std::env::set_var("PROTOC", protoc);
    println!("cargo:rerun-if-changed=../../proto/relay/v1/relay.proto");
    prost_build::compile_protos(&["../../proto/relay/v1/relay.proto"], &["../../proto"])?;
    Ok(())
}
