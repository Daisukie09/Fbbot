module.exports.config = {
        name: "confessmsg",
        version: "1.0.7",
        role: 0,
        credits: "syntaxt0x1c", // fix by light
        description: "confessmsg [uid] [text]",
        hasPrefix: true,
  commandCategory: "confess",
        usages: "ID [Text]",
        cooldowns: 5
};

module.exports.run = async ({ api, event, args }) => {
 //if (!args[0]) return api.sendMessage(`${api.getthreadID()}`, event.threadID);

        var idbox = args[0];
    var reason = args.slice(1);
        //let threadID = await api.getThreadID();
        if (args.length == 0) api.sendMessage("Syntax error, use: sendmsg ID_BOX [messsage]", event.threadID, event.messageID);

        else if(reason == "")api.sendMessage("Syntax error, use: sendmsg ID_BOX [message]", event.threadID, event.messageID);

        else
                api.sendMessage("𝗦𝗼𝗺𝗲𝗼𝗻𝗲 𝗯𝗼𝘁 𝘂𝘀𝗲𝗿 𝗵𝗮𝘀 𝗰𝗼𝗻𝗳𝗲𝘀𝘀 𝗼𝗻 𝘆𝗼𝘂, 𝗵𝗲𝗿𝗲 𝗶𝘀 𝘁𝗵𝗲 𝗰𝗼𝗻𝗳𝗲𝘀𝘀 𝗽𝗹𝗲𝗮𝘀𝗲 𝗿𝗲𝗮𝗱 𝗶𝘁.\n\nMessage: " + reason.join(" "), idbox, () =>
                        api.sendMessage(`${api.getCurrentUserID()}`, () =>
                                api.sendMessage("Sent message: " + reason.join(" "), event.threadID)));
  }
