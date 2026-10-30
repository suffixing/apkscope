// Embed the icon in the Windows executable (Explorer, taskbar, Alt-Tab).
fn main() {
    println!("cargo:rerun-if-changed=assets/apkscope.rc");
    println!("cargo:rerun-if-changed=assets/apkscope.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let _ = embed_resource::compile("assets/apkscope.rc", embed_resource::NONE);
    }
}
