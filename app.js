#!/usr/bin/env node

const debug = require("debug")("encryptor");

const program = require("commander");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const execSync = require("child_process").execSync;
const spawnSync = require("child_process").spawnSync;

const {
  fconfig,
  keyEncoder,
  getConfig,
  readMeta,
  encrypt,
  decrypt,
  waitStreamClose
} = require("./lib");

program
  .command("init <email>")
  .description("create asymetric key")
  .option("-f, --force", "Overwrite existing config")
  .action((email, options) => {
    if (fs.existsSync(fconfig) && !options.force) {
      console.log("config already exist. use --force to overwrite");
      process.exit(1);
    }
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    if (!re.test(String(email).toLowerCase())) {
      console.log("Invalid email");
      process.exit(1);
    }
    const key = crypto.createECDH("secp256k1");
    key.generateKeys();

    const pkeyPem = keyEncoder.encodePrivate(key.getPrivateKey(), "raw", "pem");
    const sig = crypto.createSign("sha512");
    sig.update(JSON.stringify({ email, pub: key.getPublicKey("base64") }));
    const config = {
      email,
      sig: sig.sign(pkeyPem, "base64"),
      key: key.getPrivateKey("base64"),
      editor: "code --wait"
    };
    fs.writeFileSync(fconfig, JSON.stringify(config, undefined, 2));
  });

program
  .command("invite")
  .description("create request command")
  .action(() => {
    const { config, upub } = getConfig();
    const invite = {
      email: config.email,
      pub: upub,
      sig: config.sig
    };
    console.log(JSON.stringify(invite, undefined, 2));
  });

program
  .command("cat <file>")
  .description("view encrypted file")
  .action(async fn => {
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    try {
      const { meta, aesKey } = await readMeta(fn);
      await decrypt(fn, meta, aesKey, process.stdout);
      console.log();
    } catch (err) {
      debug(err);
      console.log(err.message);
      process.exit(1);
    }
  });

program
  .command("edit <file>")
  .description("edit encrypted file")
  .action(async fn => {
    const { config } = getConfig();
    const ftmp = path.join(
      path.dirname(fn),
      "." +
        path.basename(fn, path.extname(fn)) +
        ".encryptor" +
        path.extname(fn)
    );
    try {
      const { meta, aesKey } = await readMeta(fn);
      const otmp = fs.createWriteStream(ftmp);
      await decrypt(fn, meta, aesKey, otmp);
      otmp.close();
      await waitStreamClose(otmp);
      execSync(`${config.editor} ${ftmp}`);
      await encrypt(fn, meta, aesKey, ftmp);
      fs.unlinkSync(ftmp);
    } catch (err) {
      debug(err);
      console.log(err.message);
      fs.unlinkSync(ftmp);
      process.exit(1);
    }
  });

program.command("contact [arguments...]").description("manage contacts");

program.command("user [arguments...]").description("manage user access");

program.on("command:contact", () => {
  const argv = process.argv;
  argv[1] = path.join(__dirname, "contact.js");
  argv.splice(2, 1);
  debug(argv);
  spawnSync(argv[0], argv.slice(1), {
    stdio: "inherit"
  });
});

program.on("command:user", () => {
  const argv = process.argv;
  argv[1] = path.join(__dirname, "user.js");
  argv.splice(2, 1);
  debug(argv);
  spawnSync(argv[0], argv.slice(1), {
    stdio: "inherit"
  });
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
