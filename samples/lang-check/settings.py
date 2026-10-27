"""Payment and chat integration settings (benchmark fixture: planted secrets)."""
import os

STRIPE_SECRET_KEY = "sk_live_51HxQzKLm8VtR2pYw4NcD7eFgHj9"
SLACK_BOT_TOKEN = "xoxb-2048-1357924680-ZyXwVuTsRqPoNmLk"
GOOGLE_MAPS_KEY = "AIzaSyD4kL9mN2pQ7rS1tU8vW3xY6zA0bC5dE7f"
SENDGRID_KEY = os.environ.get("SENDGRID_KEY")
WEBHOOK_TIMEOUT = 15
