fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=rss.ico");
        println!("cargo:rerun-if-changed=app.manifest");

        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("rss.ico");
        resource.set_manifest_file("app.manifest");

        if let Err(error) = resource.compile() {
            println!("cargo:warning=failed to embed windows resources: {error}");
        }
    }
}
