use std::env;

pub struct Config {
    pub token: String,
}

impl Config {
    pub fn get() -> Self {
        Self {
            token: env::var("DISCORD_TOKEN").expect("DISCORD_TOKEN must be set"),
        }
    }
}
