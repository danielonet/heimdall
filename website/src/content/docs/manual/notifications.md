---
title: Notifications
description: Push, Telegram and email alerts, and the test button for each.
---

:::note[Draft]
This page has not yet been checked against a running dashboard.
:::

Notifications is where Heimdall learns how to reach you when the dashboard is closed. There is one panel for each channel: **Push — ntfy.sh** (paste a topic URL), **Telegram** (a bot token and a channel) and **Email — SMTP** (server, port, STARTTLS, username, password, from, and an optional to). Each panel has its own **Save** button, which stays greyed out until you change something.

All channels get the same events: an immediate message when a CRITICAL alert fires, and a daily digest at 7 am covering everything else, with an all-clear on a quiet day. Leave a channel blank to turn it off. Changes apply at once. Each channel has a test button (see below).

## Check that a channel works

Each channel on **Notifications** has its own test button: **Send test** (ntfy), **Send test message** (Telegram) and **Send test email**. Each one sends a short message through the settings you have already **saved** (the button is greyed out while there are unsaved changes, so save first) and shows a green "Sent" or a red reason underneath. The reason is in plain words, for example that the mail server rejected the password, that the server could not be reached, or that the topic address is wrong. It never shows your password, token or topic address. A green result means the message left Heimdall and the service accepted it; for email, still look in the inbox and the spam folder.

## Email, Telegram and push

Step-by-step setup for each channel, including a Gmail example, the Telegram bot and ntfy, is in [Guide: set up notifications](/manual/notifications-setup/).
