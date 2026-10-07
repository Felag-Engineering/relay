fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // prost-build (used by tonic-build) respects PROTOC when no system protoc is installed.
    std::env::set_var("PROTOC", protoc);
    println!("cargo:rerun-if-changed=../../../proto/relay/v1/relay.proto");
    // The daemon is a gRPC client only (the Relay is the server), so generate clients,
    // not servers. The Tunnel RPC is named `Open` (not `Connect`) to avoid colliding with
    // tonic's generated client `connect()` constructor — see the proto / ADR-0005.
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["../../../proto/relay/v1/relay.proto"],
            &["../../../proto"],
        )?;
    Ok(())
}
