const axios = require('axios');

module.exports.config = {
  name: 'help',
  version: '2.0.0',
  role: 0,
  hasPrefix: true,
  aliases: ['info'],
  description: "Beginner's guide",
  usage: "Help [page] or [command]",
  credits: "syntaxt0x1c",
};

module.exports.run = async function({ api, event, enableCommands, args, Utils, prefix }) {
  const input = args.join(' ');
  try {
    const eventCommands = enableCommands[1].handleEvent;
    const commands = enableCommands[0].commands;

    // === No input → Show first page ===
    if (!input) {
      const perPage = 20;
      let page = 1;
      let start = (page - 1) * perPage;
      let end = start + perPage;

      let helpMessage = 
`🌐━━━━━━━━━━━━━━🌐
✨ 𝗕𝗼𝘁 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 𝗟𝗶𝘀𝘁 ✨
━━━━━━━━━━━━━━━━━━━

📌 Commands:\n`;

      for (let i = start; i < Math.min(end, commands.length); i++) {
        helpMessage += `   🔹 ${prefix}${commands[i]}\n`;
      }

      helpMessage += `\n⚡ Event Commands:\n`;
      eventCommands.forEach((eventCommand, index) => {
        helpMessage += `   🔸 ${prefix}${eventCommand}\n`;
      });

      helpMessage += 
`\n📖 Page ${page}/${Math.ceil(commands.length / perPage)}
➡️ Use '${prefix}help <page>' to see more
➡️ Use '${prefix}help <command>' for details
━━━━━━━━━━━━━━━🌐`;

      return api.sendMessage(helpMessage, event.threadID, event.messageID);
    }

    // === Page number input ===
    else if (!isNaN(input)) {
      const page = parseInt(input);
      const perPage = 20;
      let start = (page - 1) * perPage;
      let end = start + perPage;

      let helpMessage = 
`🌐━━━━━━━━━━━━━━🌐
✨ 𝗕𝗼𝘁 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 𝗟𝗶𝘀𝘁 ✨
━━━━━━━━━━━━━━━━━━━

📌 Commands (Page ${page}):\n`;

      for (let i = start; i < Math.min(end, commands.length); i++) {
        helpMessage += `   🔹 ${prefix}${commands[i]}\n`;
      }

      helpMessage += `\n⚡ Event Commands:\n`;
      eventCommands.forEach((eventCommand, index) => {
        helpMessage += `   🔸 ${prefix}${eventCommand}\n`;
      });

      helpMessage += 
`\n📖 Page ${page}/${Math.ceil(commands.length / perPage)}
━━━━━━━━━━━━━━━🌐`;

      return api.sendMessage(helpMessage, event.threadID, event.messageID);
    }

    // === Specific command info ===
    else {
      const command = [...Utils.handleEvent, ...Utils.commands].find(([key]) => key.includes(input?.toLowerCase()))?.[1];
      if (command) {
        const { name, version, role, aliases = [], description, usage, credits, cooldown, hasPrefix } = command;

        const roleMessage = role !== undefined ? 
          (role === 0 ? '👤 User' : 
           role === 1 ? '🛠 Admin' : 
           role === 2 ? '👑 Thread Admin' : 
           role === 3 ? '🌌 Super Admin' : '') : '';

        let message = 
`📖━━━━━━━━━━━━━━📖
✨ 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 𝗜𝗻𝗳𝗼 ✨
━━━━━━━━━━━━━━━━━━━

🔹 Name: ${name}
🔸 Version: ${version || "1.0"}
🔹 Role: ${roleMessage}
🔸 Aliases: ${aliases.length ? aliases.join(', ') : "None"}

📜 Description: ${description || "No description"}
📌 Usage: ${usage || "N/A"}
💳 Credits: ${credits || "Unknown"}
⏳ Cooldown: ${cooldown ? cooldown + "s" : "None"}

━━━━━━━━━━━━━━━📖`;

        return api.sendMessage(message, event.threadID, event.messageID);
      } else {
        return api.sendMessage('❌ Command not found.', event.threadID, event.messageID);
      }
    }
  } catch (error) {
    console.log(error);
  }
};

module.exports.handleEvent = async function({ api, event, prefix }) {
  const { threadID, messageID, body } = event;
  const message = prefix ? `⚡ My prefix is: ${prefix}` : "⚠️ Sorry, I don't have a prefix set.";
  if (body?.toLowerCase().startsWith('prefix')) {
    api.sendMessage(message, threadID, messageID);
  }
};
