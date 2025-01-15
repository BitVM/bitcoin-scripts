use std::collections::HashMap;

use risc0_build::{DockerOptions, GuestOptions};

fn main() {
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    let mut options = HashMap::new();

    let use_docker = if std::env::var("REPR_GUEST_BUILD").is_ok() {
        let this_package_dir = std::env!("CARGO_MANIFEST_DIR");
        let root_dir = format!("{this_package_dir}/../../");
        Some(DockerOptions {
            root_dir: Some(root_dir.into()),
        })
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        None
    };

    options.insert(
        "final-spv-guest",
        GuestOptions {
            use_docker,
            ..Default::default()
        },
    );

    risc0_build::embed_methods_with_options(options);
}
