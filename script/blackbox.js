const axios = require('axios');

module.exports.config = {
    name: 'blackbox',
    version: '1.0.0',
    role: 0,
    hasPrefix: false,
    aliases: ['blackbox', 'bb'],
    description: 'nigga black',
    usage: 'blackbox tas tanong bugok',
    credits: "syntaxt0x1c",
    cooldown: 3,
};

module.exports.run = async function({ api, event, args }) {
    const bulag = args.join(' ');

    if (!bulag) {
        api.sendMessage('Please provide a question, for example: blackbox what is the meaning of life?', event.threadID, event.messageID);
        return;
    }

    api.sendMessage('🔄 Searching, please wait...', event.threadID, event.messageID);

    try {
        const pangit = await axios.get('https://api.kenliejugarap.com/blackbox-pro', {
            params: { text: bulag }
        });
        const mapanghi = pangit.data;

        const responseString = mapanghi.data ? mapanghi.data : JSON.stringify(mapanghi, null, 2);

        api.sendMessage(responseString, event.threadID, event.messageID);

    } catch (error) {
        console.error('Error:', error);
        api.sendMessage('An error occurred while fetching the response.', event.threadID, event.messageID);
    }
};
