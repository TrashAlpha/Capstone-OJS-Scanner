import logging
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

BOT_USERNAME = os.getenv('TELEGRAM_BOT_USERNAME', '')


def build_start_message(chat_id: int, first_name: str | None) -> str:
    greeting = f'Hi {first_name}!' if first_name else 'Hello!'
    return '\n'.join([
        greeting,
        '',
        'Your Telegram Chat ID is:',
        str(chat_id),
        '',
        'Copy this Chat ID into the Telegram Alerts page in the dashboard to receive scan notifications.',
    ])


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_chat or not update.effective_message:
        return

    await update.effective_message.reply_text(
        build_start_message(update.effective_chat.id, update.effective_user.first_name if update.effective_user else None)
    )


async def chatid_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start_command(update, context)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return

    bot_ref = f'@{BOT_USERNAME}' if BOT_USERNAME else 'this bot'
    await update.effective_message.reply_text(
        '\n'.join([
            f'Use {bot_ref} to get your Telegram Chat ID.',
            '',
            'Available commands:',
            '/start - show your Chat ID',
            '/chatid - show your Chat ID again',
        ])
    )


def main() -> None:
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        raise RuntimeError('TELEGRAM_BOT_TOKEN is required for telegram-bot service')

    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler('start', start_command))
    app.add_handler(CommandHandler('chatid', chatid_command))
    app.add_handler(CommandHandler('help', help_command))

    logger.info('Telegram bot polling started')
    app.run_polling(drop_pending_updates=True)


if __name__ == '__main__':
    main()
