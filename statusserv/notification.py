from datetime import datetime
from statusserv.models import User
from discord_webhook import DiscordWebhook, DiscordEmbed

def sendWebhookNotification(user: User, message: str = None):
    notificationStore: list[str] = user.notification.split(";")
    if notificationStore != 2:
        return
    if notificationStore[0] != "discord":
        return
    url: str = notificationStore[1]
    webhook = DiscordWebhook(url=url, username="StatusServer")
    embed = DiscordEmbed(title="Server Ausfall", description=message, color="FF0000")
    embed.set_author(name=user.name)
    embed.set_footer(text="StatusServer by Jonathan Beyer")
    embed.set_timestamp(datetime.now())
    webhook.add_embed(embed)
    response = webhook.execute()