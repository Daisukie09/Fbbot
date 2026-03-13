# Auto Messenger Bot

## Overview
A Facebook Messenger bot with an Express.js web control panel. The bot uses the `nova-fca` library (a custom Facebook Chat API) to interact with Facebook Messenger. Users manage the bot through a web UI served on port 5000.

## Architecture
- **Runtime**: Node.js 20
- **Entry point**: `index.js` (spawns `auto.js` with auto-restart on exit code 1)
- **Main logic**: `auto.js` — Express server + bot login + command handling
- **Bot API**: `nova-fca/` — custom Facebook Chat API library
- **Web UI**: `public/` — static HTML/CSS/JS control panel (served by Express)
- **Scripts**: `script/` — bot command modules loaded at startup

## Key Files
- `index.js` — launcher with auto-restart logic
- `auto.js` — main application: Express server (port 5000), Facebook login, command routing
- `data/config.json` — bot configuration (admin IDs, FCA options)
- `data/database.json` — thread/group database
- `data/history.json` — message history
- `admin.json` — admin user list
- `public/` — web control panel (index.html, styles.css, script.js, guide.html, online.html)
- `script/` — bot command modules (ai.js, help.js, music.js, etc.)

## Configuration
- Port: **5000** (bound to 0.0.0.0)
- Config: `data/config.json` — contains masterKey (admin IDs, devMode) and fcaOption settings
- Bot requires a Facebook appstate (cookie session) submitted via the `/login` endpoint

## Workflow
- **Start application**: `node index.js` on port 5000 (webview)

## Deployment
- Target: **vm** (always-running, needed for persistent MQTT connections)
- Run: `node index.js`
