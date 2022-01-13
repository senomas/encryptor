const debug = require("debug")("encryptor");

const fs = require("fs");
const os = require("os");
const path = require("path");
const program = require("commander");
const crypto = require("crypto");
const KeyEncoder = require("key-encoder");
const spawn = require("child_process").spawn;

const keyEncoder = new KeyEncoder("secp256k1");

const { getConfig, getContacts, saveContacts, fcontact } = require("./lib");

program
  .command("list")
  .option("--config <config>")
  .description("show contact")
  .action(async fn => {
    Object.entries(getContacts()).forEach(([email, user]) => {
      console.log(email);
      console.log(`   ${user.pub}`);
    });
  });

program
  .command("add")
  .option("-e, --editor <editor>")
  .option("--config <config>")
  .description("add contact")
  .option("-f, --force", "Overwrite existing alias")
  .action(async (options) => {
    const { config } = getConfig(options);
    const contacts = getContacts();
    const ftmp = path.join(os.tmpdir(), ".seno-encryptor-contact.json");
    try {
      const editor = options.editor || config.editor;
      await new Promise((resolve, reject) => {
        const child = spawn(
          editor.split(" ")[0],
          editor
            .split(" ")
            .slice(1)
            .concat(ftmp),
          { stdio: "inherit" }
        );
        child.on("exit", code => {
          debug("exit", code);
          resolve(code);
        });
      });
      const user = JSON.parse(fs.readFileSync(ftmp));
      const pubPem = keyEncoder.encodePublic(
        Buffer.from(user.pub, "base64"),
        "raw",
        "pem"
      );
      const sig = crypto.createVerify("sha512");
      const ux = Object.assign({}, user);
      delete ux.sig;
      sig.update(JSON.stringify(ux));
      if (!sig.verify(pubPem, Buffer.from(user.sig, "base64"))) {
        throw new Error(`Invalid user signature`);
      }
      contacts[user.email] = user;
      saveContacts(contacts);
      fs.unlinkSync(ftmp);
    } catch (err) {
      debug(err);
      console.log(err.message);
      fs.unlinkSync(ftmp);
      process.exit(1);
    }
  });

program
  .command("remove <email>")
  .option("--config <config>")
  .description("remove contact")
  .action(async (alias, options) => {
    const contacts = getContacts();
    delete contacts[alias];
    saveContacts(contacts);
  });

program.on("command:*", () => {
  program.help();
  process.exit(1);
});

if (process.argv.length <= 2) {
  program.help();
  process.exit(1);
}

program.parse(process.argv);
