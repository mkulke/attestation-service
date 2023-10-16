use anyhow::Result;
use attestation_service::verifier::tdx::quote;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let quote_bin = fs::read("./td_quote.bin")?;
    let _ = quote::ecdsa_quote_verification(quote_bin.as_slice()).await?;
    Ok(())
}
