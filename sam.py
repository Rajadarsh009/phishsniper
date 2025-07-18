import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
from telegram.helpers import escape_markdown

# ======= Config ========
TG_BOT_TOKEN = "8118073077:AAHkfj4QAmnrttPRsQpCHSfmF5rM1k7R4PQ"
VT_API_KEY = "fd177b34cb5eefe329e5a9f861f0fb6dde0fce797cfa820bf660da9df5ae8123"
# =======================


# Scan URL via VirusTotal
def scan_url(url):
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

    if res.status_code == 200:
        return res.json()["data"]["id"]
    return None


# Get scan report using ID
def get_report(scan_id):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    res = requests.get(url, headers=headers)

    if res.status_code == 200:
        return res.json()
    return None


# Format report
def build_report(data):
    stats = data["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    report = f"""🔍 *Scan Report*
🧨 *Malicious:* `{malicious}`
⚠️ *Suspicious:* `{suspicious}`
❌ *Undetected:* `{undetected}`
"""
    return report


# Handle incoming messages
async def handle_msg(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    url = escape_markdown(url)  # protect from markdown break
    await update.message.reply_text("🔄 Scanning URL via VirusTotal...")

    scan_id = scan_url(url)
    if scan_id:
        data = get_report(scan_id)
        if data:
            report = build_report(data)
            await update.message.reply_markdown(report)
        else:
            await update.message.reply_text("❌ Error getting report.")
    else:
        await update.message.reply_text("❌ Failed to scan URL.")


# Start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Welcome to VirusTotal Scanner Bot!\nSend me any URL to scan.")


# Setup bot
app = ApplicationBuilder().token(TG_BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_msg))

print("🤖 Bot running...")

app.run_polling()