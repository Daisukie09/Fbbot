// Define the module configuration
module.exports.config = {
    name: "fbcover",
    version: "1.0.0",
    role: 0,
    credits: "syntaxt0x1c",
    description: "Generate a Facebook cover image",
    hasPrefix: true,
    aliases: ["fbcoverv2", "fbcv2"],
    usage: "[fbcoverv2 <name> <color> <address> <email> <subname> <sdt> <uid>]",
    cooldown: 5
};

const axios = require("axios");
const fs = require("fs");
const path = require("path");

module.exports.run = async function({ api, event, args }) {
    try {
        // Destructure the arguments
        const [name, color, address, email, subname, sdt, uid] = args;

        // Check if all required arguments are provided
        if (!name || !color || !address || !email || !subname || !sdt || !uid) {
            api.sendMessage("Usage: fbcoverv2 <name> <color> <address> <email> <subname> <sdt> <uid>", event.threadID);
            return;
        }

        // Construct the API URL with the new structure
        const url = `https://joshweb.click/canvas/fbcover?name=${encodeURIComponent(name)}&color=${encodeURIComponent(color)}&address=${encodeURIComponent(address)}&email=${encodeURIComponent(email)}&subname=${encodeURIComponent(subname)}&sdt=${encodeURIComponent(sdt)}&uid=${encodeURIComponent(uid)}`;
        const imagePath = path.join(__dirname, "fbcoverv2.png");

        // Notify the user that the image is being generated
        api.sendMessage("Generating your Facebook cover, please wait...", event.threadID);

        // Fetch the image from the API
        const response = await axios({
            url: url,
            method: 'GET',
            responseType: 'stream'
        });

        // Create a writable stream to save the image
        const writer = fs.createWriteStream(imagePath);
        response.data.pipe(writer);

        // Handle the finish event of the writable stream
        writer.on('finish', () => {
            // Send the image as an attachment
            api.sendMessage({
                attachment: fs.createReadStream(imagePath)
            }, event.threadID, () => {
                // Clean up the file after sending
                fs.unlinkSync(imagePath);
            });
        });

        // Handle errors during the writing process
        writer.on('error', (err) => {
            console.error('Stream writer error:', err);
            api.sendMessage("An error occurred while processing the request.", event.threadID);
        });
    } catch (error) {
        console.error('Error:', error);
        api.sendMessage("An error occurred while processing the request.", event.threadID);
    }
};
