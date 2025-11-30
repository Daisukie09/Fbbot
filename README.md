# AUTOBOT

A Node.js Facebook Messenger bot framework powered by `nova-fca` (rebranded and maintained by `syntaxt0x1c`). It includes a modular command system under `script/`, a simple web UI under `public/`, and persistent data under `data/`.

## Features
- Modular commands in `script/` loaded automatically.
- Messenger API via `nova-fca` with improved relogin and thread handling.
- Simple Express web UI in `public/`.
- Persistent app state and bot storage in `data/`.

## Requirements
- Node.js 16+ recommended (>= 10.x supported by nova-fca).
- A Facebook account appstate (cookies) saved to `data/session/*.json`.
- Windows PowerShell environment (commands below use PowerShell).

## Installation
```powershell
# From the project root
npm install
```

## Configuration
- `data/config.json`: Global bot config (prefix, ports, toggles).
- `data/database.json`: Command storage/user data.
- `data/history.json`: Action history/logs.
- `data/session/*.json`: AppState files (cookies). Place your session JSON here, e.g. `data/session/123456789.json`.

## Running
```powershell
# Start the bot
node auto.js

# Alternative entry (if present)
node index.js
```

If the bot fails to start, verify:
- Your appstate JSON exists in `data/session/` and is valid.
- `auto.js` references `./nova-fca/index` correctly and loads your session.
- Network connectivity to Facebook endpoints.

## Updating
```powershell
# Pull latest changes
git pull

# Install any new dependencies
npm install
```

## Folder Structure
- `nova-fca/`: Messenger API library (local, rebranded).
- `script/`: Bot command modules (each file exports `config` and `run`).
- `public/`: Web UI assets (HTML/CSS/JS).
- `data/`: Config, database, sessions, and history.
- `auto.js`: Main bootstrap for the bot.
- `index.js`: Secondary entry/server setup.

## Creating a Command
Create a new file under `script/yourcmd.js`:
```js
module.exports.config = {
  name: "yourcmd",
  role: 0,
  credits: "syntaxt0x1c",
  description: "Describe your command",
  hasPrefix: false,
  version: "1.0.0",
  aliases: [],
  usage: "yourcmd [args]"
};

module.exports.run = async function ({ api, event, args }) {
  api.sendMessage("Hello from yourcmd!", event.threadID);
};
```
Restart the bot to load the new command.

## AppState (Session) Tips
- Use a cookies editor or trusted getter to produce appstate JSON.
- Place it in `data/session/` and ensure the bot is configured to load it.

## Troubleshooting
- Error 1545012 when sending to groups: Ensure thread type caching and auto-accept logic are enabled via the included `nova-fca` updates.
- Login checkpoints: Log in via browser and verify the account, then refresh appstate.
- Attachments not sending: Confirm readable streams and supported types.

## Credits
- `syntaxt0x1c`

## License
- MIT
