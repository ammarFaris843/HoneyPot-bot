import discord
import os
import json
import asyncio
from datetime import datetime, timedelta, timezone
import asyncpg

from keep_alive import keep_alive

keep_alive()

DATABASE_URL = os.getenv('DATABASE_URL')
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.guilds = True
intents.members = True

client = discord.Client(intents=intents)

CONFIG_FILE = "src/config.json"
BOT_OWNERS = {322362428883206145}

# untested asyncpg functions for future use
async def get_guild_config(guild_id):
    conn = await asyncpg.connect(DATABASE_URL)
    record = await conn.fetchrow("SELECT * FROM guilds WHERE guild_id=$1", guild_id)
    if not record:
        await conn.execute(
            "INSERT INTO guilds(guild_id) VALUES($1)", guild_id
        )
        record = await conn.fetchrow("SELECT * FROM guilds WHERE guild_id=$1", guild_id)
    await conn.close()
    return dict(record)

async def save_guild_config(guild_id, honeypot_channel_id=None, log_channel_id=None, ban_reason=None):
    conn = await asyncpg.connect(DATABASE_URL)
    await conn.execute("""
        INSERT INTO guilds(guild_id, honeypot_channel_id, log_channel_id, ban_reason)
        VALUES($1, $2, $3, $4)
        ON CONFLICT (guild_id) DO UPDATE SET
            honeypot_channel_id = EXCLUDED.honeypot_channel_id,
            log_channel_id = EXCLUDED.log_channel_id,
            ban_reason = EXCLUDED.ban_reason
    """, guild_id, honeypot_channel_id, log_channel_id, ban_reason)
    await conn.close()

# static config use , integrated with asyncpg functions for future migration    (remove if cause errors)
# def load_config():
#     try:
#         with open(CONFIG_FILE, 'r') as f:
#             return json.load(f)
#     except FileNotFoundError:
#         return {"guilds": {}}
#
#
# def save_config(config):
#     os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
#     with open(CONFIG_FILE, 'w') as f:
#         json.dump(config, f, indent=4)
#
#
# config = load_config()
#
#
# def get_guild_config(guild_id):
#     """Get configuration for a specific guild"""
#     if "guilds" not in config:
#         config["guilds"] = {}
#     if str(guild_id) not in config["guilds"]:
#         config["guilds"][str(guild_id)] = {
#             "honeypot_channel_id": None,
#             "log_channel_id": None,
#             "ban_reason": "Automatic ban: Suspected compromised account/bot"
#         }
#         save_config(config)
#     return config["guilds"][str(guild_id)]
#
#
# def save_guild_config(guild_id, guild_config):
#     """Save configuration for a specific guild"""
#     if "guilds" not in config:
#         config["guilds"] = {}
#     config["guilds"][str(guild_id)] = guild_config
#     save_config(config)
#
#
# def get_honeypot_channel(guild):
#     guild_config = get_guild_config(guild.id)
#     if guild_config.get("honeypot_channel_id"):
#         return guild.get_channel(guild_config["honeypot_channel_id"])
#     return None
#
#
# def get_log_channel(guild):
#     guild_config = get_guild_config(guild.id)
#     if guild_config.get("log_channel_id"):
#         return guild.get_channel(guild_config["log_channel_id"])
#     return None


@client.event
async def on_ready():
    print(f'{client.user} is now online!')
    activity = discord.Activity(
        type=discord.ActivityType.watching,
        name=
        "Use !honeypothelp for setup guide. Developed and maintained by @anthropical. Officially authorized for use exclusively on Kotuh’s server."
    )
    await client.change_presence(activity=activity)

    for guild in client.guilds:
        guild_config = get_guild_config(guild.id)
        honeypot_id = guild_config.get("honeypot_channel_id")
        log_id = guild_config.get("log_channel_id")

        status = "✅" if honeypot_id and log_id else "⚠️"
        print(
            f"{status} {guild.name} (ID: {guild.id}) - Honeypot: {honeypot_id}, Log: {log_id}"
        )


def analyze_username(username):
    indicators = []
    suspicious_patterns = [
        '⛧', '卐', '••', '||', '[]', '()', '⚡', '♛', '✪', 'http', '.com', '.gg',
        'discord.gg', '000', '111', '222', '333', '444', '555', 'xxx', 'nsfw',
        'click', 'free'
    ]
    username_lower = username.lower()
    for pattern in suspicious_patterns:
        if pattern in username_lower:
            indicators.append(f"Suspicious username: '{pattern}'")
            break
    if len(username) > 25:
        indicators.append("Very long username")
    return indicators


def analyze_roles(member):
    indicators = []
    if len(member.roles) <= 1:
        indicators.append("No custom roles")
    return indicators


async def detect_suspicious_indicators(user, member):
    indicators = []
    now = datetime.now(timezone.utc)
    account_age = now - user.created_at
    if account_age < timedelta(days=1):
        indicators.append("Account <1 day old")
    elif account_age < timedelta(days=7):
        indicators.append("Account <7 days old")
    if member.joined_at:
        join_age = now - member.joined_at
        if join_age < timedelta(hours=1):
            indicators.append("Joined <1 hour ago")
        elif join_age < timedelta(hours=24):
            indicators.append("Joined <24 hours ago")
    if user.avatar is None:
        indicators.append("Default avatar")
    indicators.extend(analyze_username(user.name))
    indicators.extend(analyze_roles(member))
    return indicators


async def ban_user(member, indicators, guild):
    try:
        guild_config = get_guild_config(guild.id)
        ban_reason = guild_config.get(
            "ban_reason", "Automatic ban: Suspected compromised account/bot")
        await member.ban(reason=ban_reason +
                         f" | Indicators: {', '.join(indicators)}",
                         delete_message_days=1)
        print(f"Successfully banned {member} (ID: {member.id})")
        return True
    except discord.Forbidden:
        print(f"Missing permissions to ban {member}")
        return False
    except Exception as e:
        print(f"Error banning {member}: {e}")
        return False


async def log_detection(guild, user, message_content, indicators):
    log_channel = get_log_channel(guild)
    if not log_channel:
        return
    try:
        embed = discord.Embed(title="Honeypot Triggered",
                              color=0xffa500,
                              timestamp=datetime.now(timezone.utc))
        embed.add_field(name="User",
                        value=f"{user.mention}\n`{user}`\nID: `{user.id}`",
                        inline=False)
        truncated = message_content[:500] + "..." if len(
            message_content) > 500 else message_content
        embed.add_field(name="Message",
                        value=f"```{truncated}```",
                        inline=False)
        embed.add_field(name="Account Created",
                        value=f"<t:{int(user.created_at.timestamp())}:R>",
                        inline=True)
        embed.add_field(name="Indicators",
                        value="\n".join(indicators) if indicators else "None",
                        inline=True)
        if user.avatar:
            embed.set_thumbnail(url=user.display_avatar.url)
        await log_channel.send(embed=embed)
    except Exception as e:
        print(f"Error logging detection: {e}")


async def log_ban_result(guild, user, success, indicators):
    log_channel = get_log_channel(guild)
    if not log_channel:
        return
    try:
        color = 0x00ff00 if success else 0xff0000
        title = "User Banned" if success else "Ban Failed"
        embed = discord.Embed(title=title,
                              color=color,
                              timestamp=datetime.now(timezone.utc))
        embed.add_field(name="User",
                        value=f"{user.mention}\n`{user}`",
                        inline=False)
        embed.add_field(name="User ID", value=f"`{user.id}`", inline=True)
        embed.add_field(name="Indicators",
                        value=f"{len(indicators)}",
                        inline=True)
        if indicators:
            embed.add_field(name="Details",
                            value="• " + "\n• ".join(indicators),
                            inline=False)
        if not success:
            embed.add_field(name="Note",
                            value="Check bot permissions.",
                            inline=False)
        embed.set_footer(text="Honeypot Protection")
        await log_channel.send(embed=embed)
    except Exception as e:
        print(f"Error logging ban result: {e}")


async def handle_honeypot_trigger(message):
    try:
        member = message.guild.get_member(message.author.id)
        if not member:
            return
        indicators = await detect_suspicious_indicators(message.author, member)
        print(
            f"Honeypot triggered by {message.author} (ID: {message.author.id})"
        )
        print(f"Message: {message.content}")
        print(f"Indicators: {indicators}")
        await message.delete()
        await log_detection(message.guild, message.author, message.content,
                            indicators)
        ban_success = await ban_user(member, indicators, message.guild)
        await log_ban_result(message.guild, message.author, ban_success,
                             indicators)
    except Exception as e:
        print(f"Error processing honeypot: {e}")


def is_admin(member, guild):
    if member.id in BOT_OWNERS:
        return True
    if member.id == guild.owner_id:
        return True
    return any(role.permissions.administrator for role in member.roles)


@client.event
async def on_message(message):
    if message.author.bot:
        return

    honeypot_channel = get_honeypot_channel(message.guild)
    if honeypot_channel and message.channel.id == honeypot_channel.id:
        await handle_honeypot_trigger(message)
        return

    if message.content.startswith('!sethoneypot'):
        if not is_admin(message.author, message.guild):
            await message.channel.send("You need administrator permissions.")
            return
        parts = message.content.split()
        if len(parts) < 2:
            await message.channel.send("Usage: `!sethoneypot <channel_id>`")
            return
        try:
            channel_id = int(parts[1])
            channel = message.guild.get_channel(channel_id)
            if not channel:
                await message.channel.send("Channel not found.")
                return
            guild_config = get_guild_config(message.guild.id)
            guild_config["honeypot_channel_id"] = channel_id
            save_guild_config(message.guild.id, guild_config)
            await message.channel.send(
                f"Honeypot channel set to {channel.mention}")
        except ValueError:
            await message.channel.send("Invalid channel ID.")
        return

    if message.content.startswith('!setlog'):
        if not is_admin(message.author, message.guild):
            await message.channel.send("You need administrator permissions.")
            return
        parts = message.content.split()
        if len(parts) < 2:
            await message.channel.send("Usage: `!setlog <channel_id>`")
            return
        try:
            channel_id = int(parts[1])
            channel = message.guild.get_channel(channel_id)
            if not channel:
                await message.channel.send("Channel not found.")
                return
            guild_config = get_guild_config(message.guild.id)
            guild_config["log_channel_id"] = channel_id
            save_guild_config(message.guild.id, guild_config)
            await message.channel.send(f"Log channel set to {channel.mention}")
        except ValueError:
            await message.channel.send("Invalid channel ID.")
        return

    if message.content.startswith('!createhoneypot'):
        if not is_admin(message.author, message.guild):
            await message.channel.send("You need administrator permissions.")
            return
        parts = message.content.split(maxsplit=1)
        name = parts[1] if len(parts) > 1 else "🪤-honeypot"
        try:
            channel = await message.guild.create_text_channel(
                name,
                reason="Honeypot channel created by bot",
                topic="This channel is monitored. Do not message here.")
            guild_config = get_guild_config(message.guild.id)
            guild_config["honeypot_channel_id"] = channel.id
            save_guild_config(message.guild.id, guild_config)
            await message.channel.send(
                f"Created honeypot channel: {channel.mention}\nChannel ID: `{channel.id}`"
            )
        except Exception as e:
            await message.channel.send(f"Error creating channel: {e}")
        return

    if message.content.startswith('!createlog'):
        if not is_admin(message.author, message.guild):
            await message.channel.send("You need administrator permissions.")
            return
        parts = message.content.split(maxsplit=1)
        name = parts[1] if len(parts) > 1 else "🔍-honeypot-logs"
        try:
            channel = await message.guild.create_text_channel(
                name, reason="Log channel created by bot")
            await channel.set_permissions(message.guild.default_role,
                                          read_messages=False)
            guild_config = get_guild_config(message.guild.id)
            guild_config["log_channel_id"] = channel.id
            save_guild_config(message.guild.id, guild_config)
            await message.channel.send(
                f"Created log channel: {channel.mention}\nChannel ID: `{channel.id}`"
            )
        except Exception as e:
            await message.channel.send(f"Error creating channel: {e}")
        return

    if message.content.startswith('!honeypotconfig'):
        if not is_admin(message.author, message.guild):
            await message.channel.send("You need administrator permissions.")
            return
        honeypot = get_honeypot_channel(message.guild)
        log = get_log_channel(message.guild)
        embed = discord.Embed(title="Honeypot Configuration",
                              color=0x7289da,
                              timestamp=datetime.now(timezone.utc))
        embed.add_field(name="Honeypot Channel",
                        value=f"{honeypot.mention} (`{honeypot.id}`)"
                        if honeypot else "Not set",
                        inline=False)
        embed.add_field(
            name="Log Channel",
            value=f"{log.mention} (`{log.id}`)" if log else "Not set",
            inline=False)
        guild_config = get_guild_config(message.guild.id)
        embed.add_field(name="Ban Reason",
                        value=guild_config.get("ban_reason", "Not set"),
                        inline=False)
        embed.set_footer(text="Use !honeypothelp for commands")
        await message.channel.send(embed=embed)
        return

    if message.content.startswith('!honeypothelp'):
        embed = discord.Embed(title="Honeypot Bot Commands", color=0x00ff00)
        embed.add_field(name="!createhoneypot [name]",
                        value="Create a new honeypot channel",
                        inline=False)
        embed.add_field(name="!createlog [name]",
                        value="Create a new log channel",
                        inline=False)
        embed.add_field(name="!sethoneypot <channel_id>",
                        value="Set existing channel as honeypot",
                        inline=False)
        embed.add_field(name="!setlog <channel_id>",
                        value="Set existing channel as log",
                        inline=False)
        embed.add_field(name="!honeypotconfig",
                        value="View current configuration",
                        inline=False)
        embed.add_field(name="!honeypotstats",
                        value="View bot statistics",
                        inline=False)
        embed.set_footer(text="All commands require administrator permissions")
        await message.channel.send(embed=embed)
        return

    if message.content.startswith('!honeypotstats'):
        if not is_admin(message.author, message.guild):
            await message.channel.send("You need administrator permissions.")
            return
        honeypot = get_honeypot_channel(message.guild)
        log = get_log_channel(message.guild)
        embed = discord.Embed(title="Honeypot Statistics",
                              color=0x7289da,
                              timestamp=datetime.now(timezone.utc))
        embed.add_field(name="Server", value=message.guild.name, inline=True)
        embed.add_field(name="Honeypot Channel",
                        value=honeypot.mention if honeypot else "Not set",
                        inline=True)
        embed.add_field(name="Log Channel",
                        value=log.mention if log else "Not set",
                        inline=True)
        embed.add_field(name="Bot Latency",
                        value=f"{round(client.latency * 1000)}ms",
                        inline=True)
        embed.add_field(name="Members",
                        value=message.guild.member_count,
                        inline=True)
        status = "Active" if honeypot and log else "Setup needed"
        embed.add_field(name="Status", value=status, inline=True)
        embed.set_footer(text="Honeypot Protection System")
        await message.channel.send(embed=embed)
        return


from keep_alive import keep_alive

if __name__ == "__main__":
    keep_alive()
    token = os.getenv('DISCORD_BOT_TOKEN')
    if token:
        print("Starting honeypot bot...")
        client.run(token)
    else:
        print("ERROR: DISCORD_BOT_TOKEN not set!")
