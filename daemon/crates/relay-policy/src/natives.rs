//! The frozen Native Operation vocabulary: the four wire names (ADR-0001,
//! ADR-0012). They live in the Policy crate so the Policy linter can ask whether
//! a name is a Native without depending on the Operation registry; the registry
//! test `registry_names_are_exactly_the_native_names` pins the two together.

/// Wire name for the `system.facts` Operation.
pub const SYSTEM_FACTS: &str = "system.facts";

/// Wire name for the `file.read` Operation.
pub const FILE_READ: &str = "file.read";

/// Wire name for the `service.restart` Operation.
pub const SERVICE_RESTART: &str = "service.restart";

/// Wire name for the `pkg.install` Operation.
pub const PKG_INSTALL: &str = "pkg.install";

/// Every Native name, in canonical order.
pub const NATIVE_NAMES: [&str; 4] = [SYSTEM_FACTS, FILE_READ, SERVICE_RESTART, PKG_INSTALL];

/// Whether `name` is one of the four Natives.
pub fn is_native(name: &str) -> bool {
    NATIVE_NAMES.contains(&name)
}
