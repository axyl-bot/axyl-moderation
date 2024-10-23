mod bot;
mod commands;
mod config;
mod logging;

use bot::run_bot;

#[tokio::main]
async fn main() {
    if let Err(e) = run_bot().await {
        eprintln!("Error: {}", e);
    }
}
