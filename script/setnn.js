module.exports.config = {
  name: "setnn",
  version: "1.0.0",
  hasPermssion: 2,
  credits: "syntaxt0x1c",
  description: "Set nicknames for members who reply or are mentioned",
  commandCategory: "Utilities",
  usages: "set nickname for mentioned or replying members",
  cooldowns: 3
};

module.exports.run = async function({ api, event, args }) {
  var threadInfo = await api.getThreadInfo(event.threadID);
  var idtv = threadInfo.participantIDs; // List of all member IDs in the group
  console.log(threadInfo);
  const name = args.join(" ");

  // Initialize an empty set to store IDs of members whose nicknames will be changed
  let idsToChange = new Set();

  // If the message is a reply, add the sender of the reply to the set
  if (event.messageReply) {
    idsToChange.add(event.messageReply.senderID);
  }

  // Add mentioned users' IDs to the set
  if (event.mentions) {
    for (let mention of event.mentions) {
      idsToChange.add(mention.id);
    }
  }

  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  };

  // Loop through all participants and change the nickname only for those in the idsToChange set
  for (let setname of idtv) {
    if (idsToChange.has(setname)) { // Only change the nickname for mentioned or replying users
      await delay(3000);
      api.changeNickname(`${name}`, event.threadID, setname);
    }
  }
}
