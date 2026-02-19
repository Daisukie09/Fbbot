const axios = require('axios');

module.exports.config = {
  name: "gemini",
  role: 0,
  credits: "syntaxt0x1c",
  description: "Interact with Gemini Vision API",
  hasPrefix: false,
  version: "1.0.0",
  aliases: ["clarence", "gwapo"],
  usage: "gemini [prompt]"
};

module.exports.run = async function ({ api, event, args }) {
  const prompt = args.join(" ");

  if (!prompt) {
    return api.sendMessage('⚠️ Please provide a prompt.', event.threadID, event.messageID);
  }

  // Must be replying to a photo
  if (
    event.type !== "message_reply" ||
    !event.messageReply?.attachments?.length ||
    event.messageReply.attachments[0].type !== "photo"
  ) {
    return api.sendMessage('⚠️ Please reply to a photo with this command.', event.threadID, event.messageID);
  }

  const imageUrl = event.messageReply.attachments[0].url;
  const uid = event.senderID;
  const apiUrl = "https://geminiapi-production-3fba.up.railway.app/gemini";
  api.sendTypingIndicator(event.threadID);

  try {
    const response = await axios.get(apiUrl, {
      params: {
        ask: prompt,
        uid,
        image_url: imageUrl,
      },
    });

    const answer = response?.data?.response ?? response?.data?.result;

    if (answer) {
      return api.sendMessage(String(answer), event.threadID, event.messageID);
    } else {
      console.error("Unexpected API response:", response.data);
      return api.sendMessage(`❌ Unexpected API response.\nRaw: ${JSON.stringify(response.data)}`, event.threadID, event.messageID);
    }
  } catch (error) {
    console.error(error);
    return api.sendMessage('❌ | An error occurred while processing your request.', event.threadID, event.messageID);
  }
};
