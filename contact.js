#!/usr/bin/env node

const debug = require("debug")("encryptor");

const fs = require("fs");
const program = require("commander");
const execSync = require("child_process").execSync;
const crypto = require("crypto");
const KeyEncoder = require("key-encoder");

const keyEncoder = new KeyEncoder("secp256k1");

const { getConfig, getContacts, saveContacts, fcontact } = require("./lib");

program
  .command("list")
  .description("show contact")
  .action(async fn => {
    Object.entries(getContacts()).forEach(([alias, user]) => {
      console.log(alias);
      console.log(`   ${user.user} <${user.email}>`);
      console.log(`   ${user.pub}`);
    });
  });

program
  .command("add <alias>")
  .description("add contact")
  .option("-f, --force", "Overwrite existing alias")
  .action(async (alias, options) => {
    const { config } = getConfig();
    const contacts = getContacts();
    if (contacts[alias] && !options.force) {
      console.log("contact alias already exist. use --force to overwrite");
      process.exit(1);
    }
    try {
      execSync(`${config.editor} ${fcontact}`);
      const user = JSON.parse(fs.readFileSync(fcontact));
      const pubPem = keyEncoder.encodePublic(
        Buffer.from(user.pub, "base64"),
        "raw",
        "pem"
      );
      const sig = crypto.createVerify("sha512");
      sig.update(
        JSON.stringify({ user: user.user, email: user.email, pub: user.pub })
      );
      if (!sig.verify(pubPem, Buffer.from(user.sig, "base64"))) {
        throw new Error(`Invalid user signature`);
      }
      contacts[alias] = user;
      saveContacts(contacts);
      fs.unlinkSync(fcontact);
    } catch (err) {
      debug(err);
      console.log(err.message);
      fs.unlinkSync(fcontact);
      process.exit(1);
    }
  });

program
  .command("remove <alias>")
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
