use crate::{commands::*, config::Config};
use serenity::{
    all::*,
    async_trait,
    builder::CreateInteractionResponse,
    model::{gateway::Ready, user::OnlineStatus},
};
use sqlx::SqlitePool;

struct Handler {
    pool: SqlitePool,
}

#[async_trait]
impl EventHandler for Handler {
    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        if let Interaction::Command(command) = interaction {
            if let Err(why) = command
                .create_response(
                    &ctx.http,
                    CreateInteractionResponse::Defer(CreateInteractionResponseMessage::default()),
                )
                .await
            {
                println!("Cannot defer slash command response: {}", why);
                return;
            }

            let content = match command.data.name.as_str() {
                "kick" => kick(&ctx, &command).await,
                "ban" => ban(&ctx, &command).await,
                "unban" => unban(&ctx, &command).await,
                "mute" => mute(&ctx, &command).await,
                "unmute" => unmute(&ctx, &command).await,
                "warn" => warn(&ctx, &command).await,
                "strip_roles" => strip_roles(&ctx, &command).await,
                "purge" => purge(&ctx, &command).await,
                "mass_role" => mass_role(&ctx, &command).await,
                "role_all" => role_all(&ctx, &command).await,
                "purge_user" => purge_user(&ctx, &command).await,
                "purge_role" => purge_role(&ctx, &command).await,
                "channel_lock" => channel_lock(&ctx, &command).await,
                "channel_unlock" => channel_unlock(&ctx, &command).await,
                "slowmode" => slowmode(&ctx, &command).await,
                "userinfo" => userinfo(&ctx, &command).await,
                "serverinfo" => serverinfo(&ctx, &command).await,
                "modlog" => modlog(&ctx, &command, &self.pool).await,
                "clear_infractions" => clear_infractions(&ctx, &command).await,
                _ => "Not implemented".to_string(),
            };

            if let Err(why) = command
                .edit_response(&ctx.http, EditInteractionResponse::new().content(content))
                .await
            {
                println!("Cannot respond to slash command: {}", why);
            }
        }
    }

    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);

        ctx.set_presence(
            Some(
                ActivityData::streaming("twitch.tv/axylprojects", "https://twitch.tv/axylprojects")
                    .expect("Failed to create streaming activity"),
            ),
            OnlineStatus::DoNotDisturb,
        );

        match Command::get_global_commands(&ctx.http).await {
            Ok(commands) => {
                for command in commands {
                    if let Err(why) = Command::delete_global_command(&ctx.http, command.id).await {
                        println!(
                            "Failed to delete global command {}: {:?}",
                            command.name, why
                        );
                    } else {
                        println!("Deleted global command: {}", command.name);
                    }
                }
            }
            Err(why) => println!("Failed to get global commands: {:?}", why),
        }

        println!("Deleted all existing global commands.");

        let commands = vec![
            CreateCommand::new("kick")
                .description("Kick a user")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "The user to kick")
                        .required(true),
                )
                .add_option(CreateCommandOption::new(
                    CommandOptionType::String,
                    "reason",
                    "Reason for kicking",
                )),
            CreateCommand::new("ban")
                .description("Ban a user")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "The user to ban")
                        .required(true),
                )
                .add_option(CreateCommandOption::new(
                    CommandOptionType::String,
                    "reason",
                    "Reason for banning",
                )),
            CreateCommand::new("unban")
                .description("Unban a user")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "The user to unban")
                        .required(true),
                ),
            CreateCommand::new("mute")
                .description("Mute a user (default: 28 days)")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "The user to mute")
                        .required(true),
                )
                .add_option(CreateCommandOption::new(
                    CommandOptionType::Integer,
                    "duration",
                    "Mute duration in minutes (optional)",
                )),
            CreateCommand::new("unmute")
                .description("Unmute a user")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "The user to unmute")
                        .required(true),
                ),
            CreateCommand::new("warn")
                .description("Warn a user")
                .add_option(
                    CreateCommandOption::new(CommandOptionType::User, "user", "The user to warn")
                        .required(true),
                )
                .add_option(CreateCommandOption::new(
                    CommandOptionType::String,
                    "reason",
                    "Reason for warning",
                )),
            CreateCommand::new("strip_roles")
                .description("Remove all roles from a user")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "The user to strip roles from",
                    )
                    .required(true),
                ),
            CreateCommand::new("purge")
                .description("Purge a specified number of messages")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Integer,
                        "amount",
                        "Number of messages to purge (max 100)",
                    )
                    .required(true)
                    .min_int_value(1)
                    .max_int_value(100),
                ),
            CreateCommand::new("mass_role")
                .description("Give a user all available roles")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "The user to give all roles to",
                    )
                    .required(true),
                ),
            CreateCommand::new("role_all")
                .description("Add a specified role to all members in the server")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Role,
                        "role",
                        "The role to add to all members",
                    )
                    .required(true),
                ),
            CreateCommand::new("purge_user")
                .description("Purge messages from a specific user")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "The user whose messages to purge",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Integer,
                        "amount",
                        "Number of messages to check (default: 100)",
                    )
                    .min_int_value(1)
                    .max_int_value(1000),
                ),
            CreateCommand::new("purge_role")
                .description("Purge messages from users with a specific role")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Role,
                        "role",
                        "The role whose messages to purge",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Integer,
                        "amount",
                        "Number of messages to check (default: 100)",
                    )
                    .min_int_value(1)
                    .max_int_value(1000),
                ),
            CreateCommand::new("channel_lock").description("Lock the current channel"),
            CreateCommand::new("channel_unlock").description("Unlock the current channel"),
            CreateCommand::new("slowmode")
                .description("Set slowmode for the current channel")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::Integer,
                        "seconds",
                        "Slowmode duration in seconds",
                    )
                    .required(true)
                    .min_int_value(0)
                    .max_int_value(21600),
                ),
            CreateCommand::new("userinfo")
                .description("Display information about a user")
                .add_option(
                    CreateCommandOption::new(
                        CommandOptionType::User,
                        "user",
                        "The user to get info about",
                    )
                    .required(false),
                ),
            CreateCommand::new("serverinfo").description("Display information about the server"),
            CreateCommand::new("modlog").description("View the moderation log"),
            CreateCommand::new("clear_infractions")
                .description("Clear all infractions from the modlog"),
        ];

        match Command::set_global_commands(&ctx.http, commands).await {
            Ok(cmds) => println!("Successfully registered {} global commands", cmds.len()),
            Err(why) => println!("Failed to register global commands: {:?}", why),
        }
    }
}

pub async fn run_bot() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::get();
    let token = &config.token;
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::DIRECT_MESSAGES;

    let pool = SqlitePool::connect("sqlite:axyl_moderation.db").await?;

    let mut client = Client::builder(token, intents)
        .event_handler(Handler { pool })
        .await?;

    client.start().await?;

    Ok(())
}
