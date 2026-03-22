use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-link-lib=crypt");
    println!("cargo:rustc-link-lib=pam");

    for header in ["crypt", "pam_appl"] {
        let bindings = bindgen::Builder::default()
            .header(format!("src/{header}.h"))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join(format!("{header}.rs")))
            .expect("Couldn't write bindings!");
    }
}
