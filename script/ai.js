const axios = require('axios');

module.exports.config = {
  name: "ai",
  credits: "clarence",
  version: "1.0.0",
  role: 0,
  aliase: [""],
  cooldown: 0,
  hasPrefix: false,
};

module.exports.run = async function ({ api, event, args }) {
  try {
    const { messageID, messageReply, senderID, threadID } = event;
    let prompt = args.join(' ');


    if (messageReply) {
      const repliedMessage = messageReply.body;
      prompt = `${repliedMessage} ${prompt}`;
    }

    if (!prompt) {
      return api.sendMessage(
        '⚠️ Please provide a prompt to generate a text response.\nExample: Ai What is the meaning of life?',
        threadID,
        messageID
      );
    }


    const uid = senderID; 
    const apikey = "416866c9-979b-472f-985b-df54ad29bf79"; 
    const apiUrl = `https://python-api-clarenceai-g4d8.onrender.com/gpt4o1?prompt=${encodeURIComponent(prompt)}&uid=${uid}`;


    const response = await axios.get(apiUrl);

    if (response.data && response.data.reply) {
      api.sendMessage({ body: response.data.reply }, threadID, messageID);
    } else {
      console.error('Unexpected API response:', response.data);
      api.sendMessage(
        `❌ API returned an unexpected response.\nRaw: ${JSON.stringify(response.data)}`,
        threadID,
        messageID
      );
    }
  } catch (error) {
    console.error('Error:', error);
    api.sendMessage(
      `❌ Error occurred while generating the text response.\nDetails: ${error.message}`,
      event.threadID,
      event.messageID
    );
  }
};
