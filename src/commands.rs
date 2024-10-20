use chrono::{Duration, Utc};
use serenity::all::*;

async fn check_permissions(
    ctx: &Context,
    command: &CommandInteraction,
    permission: Permissions,
) -> bool {
    let guild_id = command.guild_id.unwrap();
    let guild = guild_id.to_partial_guild(&ctx.http).await.unwrap();
    let member = guild.member(&ctx.http, command.user.id).await.unwrap();

    println!("Checking permissions for user: {}", command.user.name);
    println!("Required permission: {:?}", permission);

    if member
        .permissions
        .unwrap_or_default()
        .contains(Permissions::ADMINISTRATOR)
    {
        println!("User is an administrator");
        return true;
    }

    if guild.owner_id == command.user.id {
        println!("User is the guild owner");
        return true;
    }

    let role_ids: Vec<RoleId> = member.roles.iter().cloned().collect();
    println!("User roles: {:?}", role_ids);

    let mut permissions = Permissions::empty();
    for role_id in role_ids {
        if let Some(role) = guild.roles.get(&role_id) {
            permissions |= role.permissions;
            println!("Role {:?} permissions: {:?}", role.name, role.permissions);
            if role.permissions.contains(Permissions::ADMINISTRATOR) {
                println!("User has administrator role");
                return true;
            }
        }
    }

    println!("Final calculated permissions: {:?}", permissions);
    println!(
        "Has required permission: {}",
        permissions.contains(permission)
    );

    permissions.contains(permission)
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

pub async fn warn(ctx: &Context, command: &CommandInteraction) -> String {
    if !check_permissions(ctx, command, Permissions::MODERATE_MEMBERS).await {
        return "You don't have permission to warn members".to_string();
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

    let dm_channel = user.create_dm_channel(&ctx.http).await;

    match dm_channel {
        Ok(channel) => {
            if let Err(why) = channel
                .say(
                    &ctx.http,
                    &format!("You have been warned. Reason: {}", reason),
                )
                .await
            {
                format!("Failed to send warning DM: {}", why)
            } else {
                format!("Successfully warned <@{}>. Reason: {}", user, reason)
            }
        }
        Err(_) => format!("Failed to create DM channel for <@{}>", user),
    }
}
