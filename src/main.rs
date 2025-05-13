use std::time::Duration;
use log::{error, info, warn};

use reqwest::Client;
use totp_rs::{Algorithm, TOTP, Secret};
use clap::Parser;

const TOTP_DIGITS: usize = 6;
const TOTP_STEP: u64 = 30;
const TOTP_ALGORITHM: Algorithm = Algorithm::SHA1;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_target(false)
        .format_timestamp(None)
        .init();
    let args = Args::parse();

    // Create the TOTP instance
    let totp = TOTP::new(
        TOTP_ALGORITHM,
        TOTP_DIGITS,
        1,
        TOTP_STEP,
        Secret::Encoded(args.secret).to_bytes()?,
    )?;

    // Generate the current TOTP code
    let token = totp.generate_current()?;
    info!("Generated TOTP token: {}", token);

    // Send the TOTP code to the local service
    let client = Client::new();
    loop {
        match client
            .get(&format!("http://localhost:4646/ffxivlauncher/{}", token))
            .timeout(Duration::from_secs(5)) // Optional: Add a timeout to avoid hanging
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    info!("TOTP token sent successfully.");
                    break;
                } else {
                    warn!("Failed to send TOTP token. Status: {}", response.status());
                }
            }
            Err(e) => {
                if e.is_connect() {
                    warn!("Connection refused. Retrying...");
                } else {
                    error!("Unexpected error: {}", e);
                }
            }
        }
    }
    
    Ok(())
}