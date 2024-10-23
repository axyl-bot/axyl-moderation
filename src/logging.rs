use serenity::{
    all::*,
    builder::{CreateEmbed, CreateMessage},
    prelude::*,
};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

pub struct LoggingConfig {
    pub log_channels: Arc<RwLock<HashMap<GuildId, ChannelId>>>,
}

impl TypeMapKey for LoggingConfig {
    type Value = Arc<LoggingConfig>;
}

impl LoggingConfig {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            log_channels: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

pub async fn log_moderation_action(
    ctx: &Context,
    guild_id: GuildId,
    moderator: &User,
    target: &User,
    action: &str,
    reason: Option<&str>,
) {
    let data = ctx.data.read().await;
    let logging_config = data.get::<LoggingConfig>().unwrap();
    let log_channels = logging_config.log_channels.read().await;

    if let Some(channel_id) = log_channels.get(&guild_id) {
        let embed = CreateEmbed::new()
            .title("Moderation Action")
            .color(0xFF0000)
            .field("Action", action, true)
            .field(
                "Moderator",
                format!("{} ({})", moderator.name, moderator.id),
                true,
            )
            .field("Target", format!("{} ({})", target.name, target.id), true)
            .field("Reason", reason.unwrap_or("No reason provided"), false)
            .timestamp(Timestamp::now());

        let message = CreateMessage::new().add_embed(embed);

        if let Err(why) = channel_id.send_message(&ctx.http, message).await {
            println!("Error sending log message: {:?}", why);
        }
    }
}

pub async fn set_log_channel(
    ctx: &Context,
    command: &CommandInteraction,
    pool: &SqlitePool,
) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_GUILD).await {
        return "You don't have permission to set the log channel".to_string();
    }

    let guild_id = command.guild_id.unwrap();
    let options = &command.data.options;
    let channel_id = options
        .iter()
        .find(|opt| opt.name == "channel")
        .and_then(|opt| opt.value.as_channel_id())
        .unwrap();

    let query = "INSERT OR REPLACE INTO log_channels (guild_id, channel_id) VALUES (?, ?)";
    if let Err(why) = sqlx::query(query)
        .bind(guild_id.get() as i64)
        .bind(channel_id.get() as i64)
        .execute(pool)
        .await
    {
        return format!("Failed to set log channel: {}", why);
    }

    let data = ctx.data.read().await;
    let logging_config = data.get::<LoggingConfig>().unwrap();
    let mut log_channels = logging_config.log_channels.write().await;
    log_channels.insert(guild_id, channel_id);

    format!("Log channel set to <#{}>", channel_id)
}

async fn check_permissions(
    ctx: &Context,
    command: &CommandInteraction,
    required_permission: Permissions,
) -> bool {
    let guild_id = command.guild_id.unwrap();
    let guild = guild_id.to_partial_guild(&ctx.http).await.unwrap();
    let member = guild.member(&ctx.http, command.user.id).await.unwrap();

    member
        .permissions
        .unwrap_or_default()
        .contains(required_permission)
        || guild.owner_id == command.user.id
}

pub async fn load_log_channel(pool: &SqlitePool, guild_id: GuildId) -> Option<ChannelId> {
    let query = "SELECT channel_id FROM log_channels WHERE guild_id = ?";
    sqlx::query_scalar::<_, i64>(query)
        .bind(guild_id.get() as i64)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|id| ChannelId::new(id as u64))
}
