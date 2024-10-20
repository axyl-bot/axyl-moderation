use crate::{commands::*, config::Config};
use serenity::{
    all::*,
    async_trait,
    builder::CreateInteractionResponse,
    model::{gateway::Ready, user::OnlineStatus},
};

struct Handler;

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
                "mute" => mute(&ctx, &command).await,
                "unmute" => unmute(&ctx, &command).await,
                "warn" => warn(&ctx, &command).await,
                "strip_roles" => strip_roles(&ctx, &command).await,
                "purge" => purge(&ctx, &command).await,
                _ => "Not implemented".to_string(),
            };

            if let Err(why) = command
                .edit_response(&ctx.http, EditInteractionResponse::new().content(content))
                .await
            {
                println!("Cannot edit slash command response: {}", why);
            }
        }
    }

    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);

        ctx.set_presence(
            Some(ActivityData::custom("Moderating")),
            OnlineStatus::DoNotDisturb,
        );

        let guild_id = Config::get().guild_id;

        let commands = GuildId::new(guild_id)
            .set_commands(
                &ctx.http,
                vec![
                    CreateCommand::new("kick")
                        .description("Kick a user")
                        .add_option(
                            CreateCommandOption::new(
                                CommandOptionType::User,
                                "user",
                                "The user to kick",
                            )
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
                            CreateCommandOption::new(
                                CommandOptionType::User,
                                "user",
                                "The user to ban",
                            )
                            .required(true),
                        )
                        .add_option(CreateCommandOption::new(
                            CommandOptionType::String,
                            "reason",
                            "Reason for banning",
                        )),
                    CreateCommand::new("mute")
                        .description("Mute a user (default: 28 days)")
                        .add_option(
                            CreateCommandOption::new(
                                CommandOptionType::User,
                                "user",
                                "The user to mute",
                            )
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
                            CreateCommandOption::new(
                                CommandOptionType::User,
                                "user",
                                "The user to unmute",
                            )
                            .required(true),
                        ),
                    CreateCommand::new("warn")
                        .description("Warn a user")
                        .add_option(
                            CreateCommandOption::new(
                                CommandOptionType::User,
                                "user",
                                "The user to warn",
                            )
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
                ],
            )
            .await;

        println!("Slash commands registered: {:#?}", commands);
    }
}

pub async fn run_bot() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::get();
    let token = &config.token;
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MEMBERS;

    let mut client = Client::builder(token, intents)
        .event_handler(Handler)
        .await?;

    client.start().await?;

    Ok(())
}
