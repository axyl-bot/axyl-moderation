use chrono::{DateTime, Duration, Utc};
use serenity::all::*;
use serenity::builder::EditChannel;
use serenity::model::guild::PremiumTier;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

async fn check_permissions(
    ctx: &Context,
    command: &CommandInteraction,
    required_permission: Permissions,
) -> bool {
    let guild_id = command.guild_id.unwrap();
    let guild = guild_id.to_partial_guild(&ctx.http).await.unwrap();
    let member = guild.member(&ctx.http, command.user.id).await.unwrap();

    println!("Checking permissions for user: {}", command.user.name);
    println!("Required permission: {:?}", required_permission);

    if member
        .permissions
        .unwrap_or_default()
        .contains(Permissions::ADMINISTRATOR)
        || guild.owner_id == command.user.id
    {
        println!("User is an administrator or the guild owner");
        return true;
    }

    let role_ids: Vec<RoleId> = member.roles.to_vec();
    println!("User roles: {:?}", role_ids);

    for role_id in role_ids {
        if let Some(role) = guild.roles.get(&role_id) {
            println!("Role {:?} permissions: {:?}", role.name, role.permissions);

            for i in 0..64 {
                let permission = Permissions::from_bits(1 << i).unwrap_or(Permissions::empty());
                if role.permissions.contains(permission) && required_permission.contains(permission)
                {
                    println!(
                        "User has the required permission {:?} through role: {:?}",
                        permission, role.name
                    );
                    return true;
                }
            }
        }
    }

    println!("User does not have the required permission");
    false
}

async fn get_everyone_role(ctx: &Context, guild_id: GuildId) -> Role {
    let guild = guild_id.to_partial_guild(&ctx.http).await.unwrap();
    guild
        .roles
        .values()
        .find(|r| r.name == "@everyone")
        .unwrap()
        .clone()
}

pub async fn kick(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::KICK_MEMBERS).await {
        return "You don't have permission to kick members".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let reason = options
        .iter()
        .find(|opt| opt.name == "reason")
        .and_then(|opt| opt.value.as_str())
        .unwrap_or("No reason provided");

    if let Err(why) = command
        .guild_id
        .unwrap()
        .kick_with_reason(&ctx.http, user, reason)
        .await
    {
        format!("Failed to kick user: {}", why)
    } else {
        let entry = format!(
            "User <@{}> was kicked by <@{}>. Reason: {}",
            user, command.user.id, reason
        );
        add_to_modlog(command.guild_id.unwrap(), entry);
        format!("Successfully kicked <@{}>. Reason: {}", user, reason)
    }
}

pub async fn ban(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::BAN_MEMBERS).await {
        return "You don't have permission to ban members".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let reason = options
        .iter()
        .find(|opt| opt.name == "reason")
        .and_then(|opt| opt.value.as_str())
        .unwrap_or("No reason provided");

    if let Err(why) = command
        .guild_id
        .unwrap()
        .ban_with_reason(&ctx.http, user, 7, reason)
        .await
    {
        format!("Failed to ban user: {}", why)
    } else {
        let entry = format!(
            "User <@{}> was banned by <@{}>. Reason: {}",
            user, command.user.id, reason
        );
        add_to_modlog(command.guild_id.unwrap(), entry);
        format!("Successfully banned <@{}>. Reason: {}", user, reason)
    }
}

pub async fn mute(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MODERATE_MEMBERS).await {
        return "You don't have permission to mute members".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let duration = options
        .iter()
        .find(|opt| opt.name == "duration")
        .and_then(|opt| opt.value.as_i64())
        .unwrap_or(28 * 24 * 60);

    let duration = duration.min(28 * 24 * 60);

    let guild = command.guild_id.unwrap();
    let mut member = match guild.member(&ctx.http, user).await {
        Ok(m) => m,
        Err(why) => return format!("Failed to fetch member: {}", why),
    };

    let mute_until = Utc::now() + Duration::minutes(duration);
    let mute_until = Timestamp::from_unix_timestamp(mute_until.timestamp()).unwrap();

    match member
        .disable_communication_until_datetime(&ctx.http, mute_until)
        .await
    {
        Ok(_) => {
            if duration == 28 * 24 * 60 {
                format!(
                    "Successfully muted <@{}> for 28 days (maximum duration)",
                    user
                )
            } else {
                format!("Successfully muted <@{}> for {} minutes", user, duration)
            }
        }
        Err(why) => format!("Failed to mute user: {}. Error details: {:?}", user, why),
    }
}

pub async fn unmute(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MODERATE_MEMBERS).await {
        return "You don't have permission to unmute members".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let guild = command.guild_id.unwrap();
    let mut member = guild.member(&ctx.http, user).await.unwrap();

    if let Err(why) = member.enable_communication(&ctx.http).await {
        format!("Failed to unmute user: {}", why)
    } else {
        format!("Successfully unmuted <@{}>", user)
    }
}

pub async fn warn(ctx: &Context, command: &CommandInteraction, pool: &SqlitePool) -> String {
    if !check_permissions(ctx, command, Permissions::MODERATE_MEMBERS).await {
        return "You don't have permission to warn users".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();
    let reason = options
        .iter()
        .find(|opt| opt.name == "reason")
        .and_then(|opt| opt.value.as_str())
        .unwrap_or("No reason provided");

    let guild_id = command.guild_id.unwrap();
    let moderator_id = command.user.id;

    let action = format!("Warned by <@{}> for reason: {}", moderator_id, reason);

    add_to_modlog(guild_id, format!("User <@{}> {}", user, action));

    let query = "INSERT INTO modlog (guild_id, user_id, action) VALUES (?, ?, ?)";
    if let Err(why) = sqlx::query(query)
        .bind(guild_id.get() as i64)
        .bind(user.get() as i64)
        .bind(action)
        .execute(pool)
        .await
    {
        println!("Error inserting into modlog: {:?}", why);
    }

    format!("Successfully warned <@{}>. Reason: {}", user, reason)
}

pub async fn strip_roles(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_ROLES).await {
        return "You don't have permission to manage roles".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let guild = command.guild_id.unwrap();
    let member = match guild.member(&ctx.http, user).await {
        Ok(m) => m,
        Err(why) => return format!("Failed to fetch member: {}", why),
    };

    let roles: Vec<RoleId> = member.roles.clone();
    if roles.is_empty() {
        return format!("<@{}> has no roles to remove", user);
    }

    match member.remove_roles(&ctx.http, &roles).await {
        Ok(_) => format!("Successfully stripped all roles from <@{}>", user),
        Err(why) => format!("Failed to strip roles: {}", why),
    }
}

pub async fn purge(ctx: &Context, command: &CommandInteraction) -> String {
    let amount = command.data.options[0].value.as_i64().unwrap();
    let channel_id = command.channel_id;

    let amount = u8::try_from(amount.min(100)).unwrap_or(100);

    let messages = channel_id
        .messages(&ctx.http, GetMessages::default().limit(amount + 1))
        .await;

    if let Err(why) = messages {
        return format!("Failed to fetch messages: {}", why);
    }

    let messages = messages.unwrap();
    let message_ids: Vec<MessageId> = messages.iter().skip(1).map(|m| m.id).collect();

    if message_ids.is_empty() {
        return "No messages to delete.".to_string();
    }

    if let Err(why) = channel_id.delete_messages(&ctx.http, &message_ids).await {
        return format!("Failed to delete messages: {}", why);
    }

    format!("Successfully purged {} messages", message_ids.len())
}

pub async fn mass_role(ctx: &Context, command: &CommandInteraction) -> String {
    const ALLOWED_USER_ID: u64 = 940285292944961537;

    if command.user.id.get() != ALLOWED_USER_ID {
        return "You are not authorized to use this command.".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let guild = command.guild_id.unwrap();
    let member = match guild.member(&ctx.http, user).await {
        Ok(m) => m,
        Err(why) => return format!("Failed to fetch member: {}", why),
    };

    let guild_roles = guild.roles(&ctx.http).await.unwrap();
    let bot_id = ctx.http.get_current_user().await.unwrap().id;
    let bot_member = guild.member(&ctx.http, bot_id).await.unwrap();

    let bot_top_role_position = bot_member
        .roles
        .iter()
        .filter_map(|r| guild_roles.get(r))
        .map(|r| r.position)
        .max()
        .unwrap_or(0);

    let roles_to_add: Vec<RoleId> = guild_roles
        .iter()
        .filter(|(role_id, role)| {
            **role_id != RoleId::from(guild.get())
                && !member.roles.contains(role_id)
                && role.position < bot_top_role_position
                && !role.permissions.contains(Permissions::ADMINISTRATOR)
        })
        .map(|(role_id, _)| *role_id)
        .collect();

    if roles_to_add.is_empty() {
        return format!(
            "<@{}> already has all available roles that can be assigned",
            user
        );
    }

    println!("Roles to add: {:?}", roles_to_add);
    println!("Bot's roles: {:?}", bot_member.roles);
    println!("Bot's top role position: {}", bot_top_role_position);

    let mut added_roles = Vec::new();
    let mut failed_roles = Vec::new();

    for role_id in roles_to_add {
        match member.add_role(&ctx.http, role_id).await {
            Ok(_) => added_roles.push(role_id),
            Err(why) => {
                println!("Failed to add role {:?}: {:?}", role_id, why);
                failed_roles.push(role_id);
            }
        }
    }

    let mut response = String::new();
    if !added_roles.is_empty() {
        response.push_str(&format!(
            "Successfully added {} roles to <@{}>. ",
            added_roles.len(),
            user
        ));
    }
    if !failed_roles.is_empty() {
        response.push_str(&format!("Failed to add {} roles. ", failed_roles.len()));
    }

    response
}

pub async fn role_all(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_ROLES).await {
        return "You don't have permission to manage roles".to_string();
    }

    let options = &command.data.options;
    let role_id = options
        .iter()
        .find(|opt| opt.name == "role")
        .and_then(|opt| opt.value.as_role_id())
        .unwrap();

    let guild = command.guild_id.unwrap();
    let members = match guild.members(&ctx.http, None, None).await {
        Ok(m) => m,
        Err(why) => return format!("Failed to fetch members: {}", why),
    };

    let mut success_count = 0;
    let mut fail_count = 0;

    for member in members {
        if !member.roles.contains(&role_id) {
            match member.add_role(&ctx.http, role_id).await {
                Ok(_) => success_count += 1,
                Err(why) => {
                    println!("Failed to add role to {:?}: {:?}", member.user.name, why);
                    fail_count += 1;
                }
            }
        }
    }

    format!(
        "Role added to {} members. Failed for {} members.",
        success_count, fail_count
    )
}

pub async fn purge_user(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_MESSAGES).await {
        return "You don't have permission to manage messages".to_string();
    }

    let options = &command.data.options;
    let user = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();
    let amount = options
        .iter()
        .find(|opt| opt.name == "amount")
        .and_then(|opt| opt.value.as_i64())
        .unwrap_or(100);

    let user_id = user;
    purge_messages(ctx, command.channel_id, amount, move |msg| {
        Box::pin(async move { msg.author.id == user_id })
    })
    .await
}

pub async fn purge_role(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_MESSAGES).await {
        return "You don't have permission to manage messages".to_string();
    }

    let options = &command.data.options;
    let role = options
        .iter()
        .find(|opt| opt.name == "role")
        .and_then(|opt| opt.value.as_role_id())
        .unwrap();
    let amount = options
        .iter()
        .find(|opt| opt.name == "amount")
        .and_then(|opt| opt.value.as_i64())
        .unwrap_or(100);

    let guild_id = command.guild_id.unwrap();
    let ctx_clone = ctx.clone();
    purge_messages(ctx, command.channel_id, amount, move |msg| {
        let ctx = ctx_clone.clone();
        let guild_id = guild_id;
        let role = role;
        Box::pin(async move {
            let member = guild_id.member(&ctx.http, msg.author.id).await;
            member.map_or(false, |m| m.roles.contains(&role))
        })
    })
    .await
}

async fn purge_messages<F, Fut>(
    ctx: &Context,
    channel_id: ChannelId,
    amount: i64,
    filter: F,
) -> String
where
    F: Fn(Message) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send,
{
    let amount = amount.min(100) as u8;
    let messages = channel_id
        .messages(&ctx.http, GetMessages::default().limit(amount))
        .await;

    if let Err(why) = messages {
        return format!("Failed to fetch messages: {}", why);
    }

    let messages = messages.unwrap();
    let mut message_ids = Vec::new();

    for msg in messages.into_iter() {
        if filter(msg.clone()).await {
            message_ids.push(msg.id);
        }
    }

    if message_ids.is_empty() {
        return "No messages to delete.".to_string();
    }

    if let Err(why) = channel_id.delete_messages(&ctx.http, &message_ids).await {
        return format!("Failed to delete messages: {}", why);
    }

    format!("Successfully purged {} messages", message_ids.len())
}

pub async fn unban(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::BAN_MEMBERS).await {
        return "You don't have permission to unban members".to_string();
    }

    let options = &command.data.options;
    let user_id = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let guild = command.guild_id.unwrap();

    if let Err(why) = guild.unban(&ctx.http, user_id).await {
        format!("Failed to unban user: {}", why)
    } else {
        format!("Successfully unbanned <@{}>", user_id)
    }
}

pub async fn channel_lock(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_CHANNELS).await {
        return "You don't have permission to lock channels".to_string();
    }

    let channel_id = command.channel_id;
    let guild = command.guild_id.unwrap();
    let everyone_role = get_everyone_role(ctx, guild).await;

    let mut channel = channel_id
        .to_channel(&ctx.http)
        .await
        .unwrap()
        .guild()
        .unwrap();
    let mut permissions = channel.permission_overwrites.clone();

    let overwrite = PermissionOverwrite {
        allow: Permissions::empty(),
        deny: Permissions::SEND_MESSAGES,
        kind: PermissionOverwriteType::Role(everyone_role.id),
    };

    permissions.push(overwrite);

    if let Err(why) = channel
        .edit(&ctx.http, EditChannel::new().permissions(permissions))
        .await
    {
        format!("Failed to lock channel: {}", why)
    } else {
        "Channel locked successfully".to_string()
    }
}

pub async fn channel_unlock(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_CHANNELS).await {
        return "You don't have permission to unlock channels".to_string();
    }

    let channel_id = command.channel_id;
    let guild = command.guild_id.unwrap();
    let everyone_role = get_everyone_role(ctx, guild).await;

    let mut channel = channel_id
        .to_channel(&ctx.http)
        .await
        .unwrap()
        .guild()
        .unwrap();
    let mut permissions = channel.permission_overwrites.clone();

    permissions.retain(|p| p.kind != PermissionOverwriteType::Role(everyone_role.id));

    if let Err(why) = channel
        .edit(&ctx.http, EditChannel::new().permissions(permissions))
        .await
    {
        format!("Failed to unlock channel: {}", why)
    } else {
        "Channel unlocked successfully".to_string()
    }
}

pub async fn slowmode(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_CHANNELS).await {
        return "You don't have permission to change slowmode".to_string();
    }

    let options = &command.data.options;
    let seconds = options
        .iter()
        .find(|opt| opt.name == "seconds")
        .and_then(|opt| opt.value.as_i64())
        .unwrap_or(0);

    let channel_id = command.channel_id;
    let mut channel = channel_id
        .to_channel(&ctx.http)
        .await
        .unwrap()
        .guild()
        .unwrap();

    if let Err(why) = channel
        .edit(
            &ctx.http,
            EditChannel::new().rate_limit_per_user(seconds as u16),
        )
        .await
    {
        format!("Failed to set slowmode: {}", why)
    } else {
        format!("Slowmode set to {} seconds", seconds)
    }
}

pub async fn userinfo(ctx: &Context, command: &CommandInteraction) -> String {
    let options = &command.data.options;
    let user_id = options
        .iter()
        .find(|opt| opt.name == "user")
        .and_then(|opt| opt.value.as_user_id())
        .unwrap_or(command.user.id);

    let guild = command.guild_id.unwrap();
    let member = guild.member(&ctx.http, user_id).await.unwrap();
    let user = &member.user;

    let guild = command
        .guild_id
        .unwrap()
        .to_partial_guild(&ctx.http)
        .await
        .unwrap();
    let roles: Vec<&Role> = member
        .roles
        .iter()
        .filter_map(|role_id| guild.roles.get(role_id))
        .collect();
    let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

    let created_at: DateTime<Utc> =
        DateTime::from_timestamp(user.created_at().unix_timestamp(), 0).unwrap();
    let joined_at: DateTime<Utc> =
        DateTime::from_timestamp(member.joined_at.unwrap().unix_timestamp(), 0).unwrap();

    let created_at_str = created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let joined_at_str = joined_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let embed = CreateEmbed::new()
        .title(format!("User Info - {}", user.name))
        .thumbnail(user.face())
        .color(0x3498db)
        .field("ID", user.id.to_string(), true)
        .field(
            "Nickname",
            member.nick.unwrap_or_else(|| "None".to_string()),
            true,
        )
        .field("Created At", created_at_str, true)
        .field("Joined At", joined_at_str, true)
        .field("Roles", role_names.join(", "), false)
        .field("Bot", user.bot.to_string(), true)
        .field("Boosting", member.premium_since.is_some().to_string(), true);

    if let Err(why) = command
        .edit_response(&ctx.http, EditInteractionResponse::new().add_embed(embed))
        .await
    {
        format!("Failed to send userinfo: {}", why)
    } else {
        "Userinfo sent successfully".to_string()
    }
}

pub async fn serverinfo(ctx: &Context, command: &CommandInteraction) -> String {
    let guild = command
        .guild_id
        .unwrap()
        .to_partial_guild(&ctx.http)
        .await
        .unwrap();

    let role_count = guild.roles.len();
    let text_channels = guild
        .channels(&ctx.http)
        .await
        .unwrap()
        .values()
        .filter(|c| c.kind == ChannelType::Text)
        .count();
    let voice_channels = guild
        .channels(&ctx.http)
        .await
        .unwrap()
        .values()
        .filter(|c| c.kind == ChannelType::Voice)
        .count();

    let created_at: DateTime<Utc> =
        DateTime::from_timestamp(guild.id.created_at().unix_timestamp(), 0).unwrap();
    let created_at_str = created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let embed = CreateEmbed::new()
        .title(format!("Server Info - {}", guild.name))
        .thumbnail(guild.icon_url().unwrap_or_default())
        .color(0x3498db)
        .field("ID", guild.id.to_string(), true)
        .field("Owner", format!("<@{}>", guild.owner_id), true)
        .field("Created At", created_at_str, true)
        .field("Roles", role_count.to_string(), true)
        .field("Text Channels", text_channels.to_string(), true)
        .field("Voice Channels", voice_channels.to_string(), true)
        .field(
            "Verification Level",
            format!("{:?}", guild.verification_level),
            true
        )
        .field(
            "Content Filter",
            format!("{:?}", guild.explicit_content_filter),
            true
        )
        .field(
            "Boost Level",
            match guild.premium_tier {
                PremiumTier::Tier0 => "0",
                PremiumTier::Tier1 => "1",
                PremiumTier::Tier2 => "2",
                PremiumTier::Tier3 => "3",
                _ => "Unknown",
            },
            true,
        )
        .field(
            "Boost Count",
            guild.premium_subscription_count.unwrap_or(0).to_string(),
            true,
        );

    if let Err(why) = command
        .edit_response(&ctx.http, EditInteractionResponse::new().add_embed(embed))
        .await
    {
        format!("Failed to send serverinfo: {}", why)
    } else {
        "Serverinfo sent successfully".to_string()
    }
}

lazy_static::lazy_static! {
    static ref MODLOG: Arc<Mutex<HashMap<GuildId, Vec<String>>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub async fn modlog(ctx: &Context, command: &CommandInteraction, pool: &SqlitePool) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_GUILD).await {
        return "You don't have permission to view the modlog".to_string();
    }

    let guild_id = command.guild_id.unwrap();
    let user_id = command
        .data
        .options
        .get(0)
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let user = match user_id.to_user(&ctx.http).await {
        Ok(user) => user,
        Err(_) => return "Failed to fetch user information".to_string(),
    };

    let query = "SELECT action FROM modlog WHERE guild_id = ? AND user_id = ? ORDER BY timestamp DESC LIMIT 10";
    let logs = sqlx::query_scalar::<_, String>(query)
        .bind(guild_id.get() as i64)
        .bind(user_id.get() as i64)
        .fetch_all(pool)
        .await;

    match logs {
        Ok(actions) => {
            if actions.is_empty() {
                format!("No moderation actions recorded for {}.", user.name)
            } else {
                let embed = CreateEmbed::new()
                    .title(format!("Moderation Log for {}", user.name))
                    .description(actions.join("\n"))
                    .color(0x3498db);

                if let Err(why) = command
                    .edit_response(&ctx.http, EditInteractionResponse::new().add_embed(embed))
                    .await
                {
                    format!("Failed to send modlog: {}", why)
                } else {
                    "Modlog sent successfully".to_string()
                }
            }
        }
        Err(e) => format!("Failed to fetch modlog: {}", e),
    }
}

pub async fn clear_infractions(
    ctx: &Context,
    command: &CommandInteraction,
    pool: &SqlitePool,
) -> String {
    if !check_permissions(ctx, command, Permissions::MANAGE_GUILD).await {
        return "You don't have permission to clear infractions".to_string();
    }

    let guild_id = command.guild_id.unwrap();
    let user_id = command
        .data
        .options
        .get(0)
        .and_then(|opt| opt.value.as_user_id())
        .unwrap();

    let query = "DELETE FROM modlog WHERE guild_id = ? AND user_id = ?";
    match sqlx::query(query)
        .bind(guild_id.get() as i64)
        .bind(user_id.get() as i64)
        .execute(pool)
        .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                format!(
                    "All infractions for <@{}> have been cleared from the modlog.",
                    user_id
                )
            } else {
                format!("No infractions found for <@{}>.", user_id)
            }
        }
        Err(e) => format!("Failed to clear infractions: {}", e),
    }
}

pub fn add_to_modlog(guild_id: GuildId, entry: String) {
    let mut modlog = MODLOG.lock().unwrap();
    modlog.entry(guild_id).or_insert_with(Vec::new).push(entry);
}
