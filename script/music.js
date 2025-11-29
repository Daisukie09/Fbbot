const path = require('path'); 
const axios = require('axios'); // For API requests

module.exports.config = {
  name: "music",
  version: "1.0.0",
  role: 0,
  hasPrefix: true,
  aliases: ['play'],
  usage: 'Music [prompt]',
  description: 'Search and download music from Spotify',
  credits: "syntaxt0x1c",
  cooldown: 5
};

module.exports.run = async function({ api, event, args }) {
  const fs = require("fs-extra");
  const musicName = args.join(' ');
  if (!musicName) {
    return api.sendMessage(`To get started, type "music" followed by the title of the song you want.`, event.threadID, event.messageID);
  }

  try {
    api.sendMessage(`Searching for "${musicName}"...`, event.threadID, event.messageID);

    // Fetch the song data from the new API
    const apiUrl = `https://hiroshi-api.onrender.com/tiktok/spotify?search=${encodeURIComponent(musicName)}`;
    const response = await axios.get(apiUrl);
    const results = response.data;

    if (!results || results.length === 0) {
      return api.sendMessage("No results found for your search.", event.threadID, event.messageID);
    }

    const music = results[0]; // Get the first result
    const { name, download, image } = music;

    api.sendMessage({
      body: `🎵 Song: ${name}\n\n🔗 [Listen on Spotify](${music.track})\n⬇️ Downloading...`,
      attachment: await axios({
        url: image,
        responseType: 'stream'
      }).then(res => res.data)
    }, event.threadID, event.messageID);

    // Download the MP3 file
    const time = new Date();
    const timestamp = time.toISOString().replace(/[:.]/g, "-");
    const filePath = path.join(__dirname, 'cache', `${timestamp}_music.mp3`);

    const downloadStream = await axios({
      url: download,
      responseType: 'stream'
    });

    downloadStream.data.pipe(fs.createWriteStream(filePath));

    downloadStream.data.on('end', () => {
      if (fs.statSync(filePath).size > 26214400) {
        fs.unlinkSync(filePath);
        return api.sendMessage('The file is too large to send (over 25MB).', event.threadID);
      }

      const message = {
        body: `🎶 Here's your song: ${name}`,
        attachment: fs.createReadStream(filePath)
      };

      api.sendMessage(message, event.threadID, () => {
        fs.unlinkSync(filePath); // Delete the file after sending
      }, event.messageID);
    });

    downloadStream.data.on('error', () => {
      api.sendMessage('Failed to download the song.', event.threadID, event.messageID);
    });

  } catch (error) {
    console.error(error);
    api.sendMessage('An error occurred while processing your request.', event.threadID, event.messageID);
  }
};
