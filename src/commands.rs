use chrono::{Duration, Utc};
use serenity::all::*;

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

    let role_ids: Vec<RoleId> = member.roles.iter().cloned().collect();
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
    if !check_permissions(ctx, command, Permissions::MANAGE_MESSAGES).await {
        return "You don't have permission to purge messages".to_string();
    }

    let options = &command.data.options;
    let amount = options
        .iter()
        .find(|opt| opt.name == "amount")
        .and_then(|opt| opt.value.as_i64())
        .unwrap_or(1)
        .min(100) as u8;

    let channel_id = command.channel_id;
    let messages = channel_id
        .messages(&ctx.http, GetMessages::default().limit(amount))
        .await;

    match messages {
        Ok(messages) => {
            let bot_id = ctx.http.get_current_user().await.unwrap().id;
            let message_ids: Vec<MessageId> = messages
                .iter()
                .filter(|m| m.author.id != bot_id)
                .map(|m| m.id)
                .collect();

            let deleted_count = message_ids.len();

            match channel_id.delete_messages(&ctx.http, message_ids).await {
                Ok(_) => format!("Successfully purged {} messages", deleted_count),
                Err(why) => format!("Failed to purge messages: {}", why),
            }
        }
        Err(why) => format!("Failed to fetch messages: {}", why),
    }
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
        response.push_str(&format!("Successfully added {} roles to <@{}>. ", added_roles.len(), user));
    }
    if !failed_roles.is_empty() {
        response.push_str(&format!("Failed to add {} roles. ", failed_roles.len()));
    }

    response
}
