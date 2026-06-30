fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // prost-build (used by tonic-build) respects PROTOC when no system protoc is installed.
    std::env::set_var("PROTOC", protoc);
    // Generate message types only for the v0.0.1 stub.
    // Service client/server generation is deferred: the Tunnel.Connect RPC name collides
    // with tonic's built-in transport connect() method and must be renamed before
    // client/server stubs can be enabled.
    tonic_build::configure()
        .build_client(false)
        .build_server(false)
        .compile_protos(&["../proto/gleipnir/v1/gleipnir.proto"], &["../proto"])?;
    Ok(())
}
