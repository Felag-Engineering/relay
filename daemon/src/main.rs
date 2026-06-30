#[allow(dead_code, unused_imports, clippy::all)]
mod gen {
    include!(concat!(env!("OUT_DIR"), "/gleipnir.v1.rs"));
}

fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("relay-daemon starting");
}
