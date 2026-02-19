const fs = require('fs');
const path = require('path');
const axios = require('axios');

module.exports.config = {
    name: "autofacebookdl",
    eventType: ["log:unsubscribe"],
    version: "1.0.0",
    credits: "syntaxt0x1c",
    description: "Listen to events and automatically download Facebook videos.",
    cooldowns: 5,
};

module.exports.handleEvent = async function({ api, event }) {
    const tempDir = path.join(__dirname, 'cache', 'facebookdl');
    const videoPath = path.join(tempDir, 'video.mp4');

    // Ensure the directory exists, if not, create it
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    const regexFB = /https:\/\/www\.facebook\.com\/\S+/;
    const match = event.body?.match(regexFB);
    const url = match ? match[0] : null;

    if (match) {
        api.setMessageReaction("⏳", event.messageID, () => {}, true);
        api.sendTypingIndicator(event.threadID, true);

        try {
            // Fetch the video download link
            const apiUrl = `https://vern-rest-api.vercel.app/api/fbdl?url=${encodeURIComponent(url)}`;
            const response = await axios.get(apiUrl);

            // Expected response: { creator: "Vern", result: "<direct mp4 url>" }
            const videoUrl = response?.data?.result;

            if (!videoUrl) {
                throw new Error("Could not retrieve video URL from the API.");
            }

            // Download sa video
            const videoData = await axios.get(videoUrl, { responseType: 'arraybuffer' });

            // mag send message tas mo ingon the video is downloading
            api.sendMessage('Downloading...', event.threadID, (err, info) => {
                setTimeout(() => {
                    api.unsendMessage(info.messageID);
                }, 10000);
            }, event.messageID);

            // Write the video to the local file system
            fs.writeFileSync(videoPath, Buffer.from(videoData.data, "binary"));

            // After 5 seconds, send the video back
            setTimeout(function() {
                api.setMessageReaction("✅", event.messageID, () => {}, true);
                return api.sendMessage({
                    body: "Downloaded Successfully.",
                    attachment: fs.createReadStream(videoPath)
                }, event.threadID, () => fs.unlinkSync(videoPath));
            }, 5000);
        } catch (e) {
            console.error(e);
            return api.sendMessage("An error occurred: " + e.message, event.threadID, event.messageID);
        }
    }
};
