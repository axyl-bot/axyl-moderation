use std::env;

pub struct Config {
    pub token: String,
    pub guild_id: u64,
}

impl Config {
    pub fn get() -> Self {
        Self {
            token: env::var("DISCORD_TOKEN").expect("DISCORD_TOKEN must be set"),
            guild_id: env::var("GUILD_ID")
                .expect("GUILD_ID must be set")
                .parse()
                .expect("GUILD_ID must be a valid u64"),
        }
    }
}
