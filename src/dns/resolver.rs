use anyhow::Result;
use hickory_resolver::TokioResolver;

/// Get a DNS resolver instance
#[cfg(any(unix, target_os = "windows"))]
pub fn get_resolver() -> Result<TokioResolver> {
    // Use system DNS configuration
    match TokioResolver::builder_tokio() {
        Ok(resolver) => Ok(resolver.build()),
        Err(e) => Err(anyhow::anyhow!("Failed to create TokioAsyncResolver: {}", e)),
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn get_resolver() -> Result<TokioAsyncResolver> {
    use hickory_resolver::name_server::TokioConnectionProvider;
    let builder = TokioResolver::builder_with_config(ResolverConfig::default(), TokioConnectionProvider::default());
    return Ok(builder.build());
}
