#!/usr/bin/env node

const debug = require("debug")("encryptor");

const os = require("os");
const program = require("commander");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const spawn = require("child_process").spawn;
const spawnSync = require("child_process").spawnSync;

const {
  keyEncoder,
  getConfig,
  readMeta,
  encrypt,
  decrypt,
  waitStreamClose
} = require("./lib");

const packageJson = JSON.parse(
  fs.readFileSync(path.join(__dirname, "package.json"))
);

program.version(packageJson.version, "-v, --version");

program
  .command("init <email>")
  .description("create asymetric key")
  .option("--config <config>")
  .option("-f, --force", "Overwrite existing config")
  .action((email, options) => {
    const fconfig = options.config
      ? options.config
      : path.join(os.homedir(), ".seno-encryptor");
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
  .option("--config <config>")
  .action(options => {
    const { config, upub } = getConfig(options);
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
  .option("--config <config>")
  .action(async (fn, options) => {
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    try {
      const { meta, aesKey } = await readMeta(fn, options);
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
  .option("-e, --editor <editor>")
  .option("--config <config>")
  .description("edit encrypted file")
  .action(async (fn, options) => {
    const { config } = getConfig(options);
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
      const editor = options.editor || config.editor;
      debug(`exec [${editor} ${ftmp}]`);
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
      await encrypt(fn, meta, aesKey, ftmp);
      fs.unlinkSync(ftmp);
    } catch (err) {
      debug(err);
      console.log(err.message);
      if (fs.existsSync(ftmp)) {
        fs.unlinkSync(ftmp);
      }
      process.exit(1);
    }
  });

program
  .command("enc <file>")
  .option("--config <config>")
  .option("-e, --editor <editor>")
  .description("edit encrypted file")
  .action(async (fn, options) => {
    const { config } = getConfig(options);
    const ftmp = path.join(
      path.dirname(fn),
      "." +
        path.basename(fn, path.extname(fn)) +
        ".encryptor" +
        path.extname(fn)
    );
    try {
      const { meta, aesKey } = await readMeta(ftmp);
      const otmp = fs.createWriteStream(ftmp);
      fs.createReadStream(fn).pipe(otmp);
      await waitStreamClose(otmp);
      const editor = options.editor || config.editor;
      debug(`exec [${editor} ${ftmp}]`);
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