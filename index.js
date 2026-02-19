const { spawn } = require("child_process");
const path = require('path');

const SCRIPT_FILE = "auto.js";
const SCRIPT_PATH = path.join(__dirname, SCRIPT_FILE);


function start() {
    const forwardedArgs = process.argv.slice(2);
    const isOneShot = forwardedArgs.some(arg =>
        arg === "--setupEmbeddedBackupSecrets" ||
        arg.startsWith("--setupEmbeddedBackupSecrets=") ||
        arg === "--encryptBackupSecrets" ||
        arg.startsWith("--encryptBackupSecrets=")
    );
    const main = spawn("node", [SCRIPT_PATH, ...forwardedArgs], {
        cwd: __dirname,
        stdio: "inherit",
        shell: true
    });

    main.on("close", (exitCode) => {
        if (exitCode === 0) {
            console.log("Main process exited with code 0");
        } else if (isOneShot) {
            console.error(`One-shot command exited with code ${exitCode}`);
            process.exit(exitCode);
        } else if (exitCode === 1) {
            console.log("Main process exited with code 1. Restarting...");
            start();
        }  else {
            console.error(`Main process exited with code ${exitCode}`);
        }
    });
}

start();

