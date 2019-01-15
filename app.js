#!/usr/bin/env node

const program = require("commander");
const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const stream = require("stream");
const KeyEncoder = require("key-encoder");
const execSync = require("child_process").execSync;
const yaml = require("js-yaml");

const fconfig = path.join(os.homedir(), ".seno-encryptor");
if (!fs.existsSync(fconfig)) {
  console.log("config not exist. init first");
  process.exit(1);
}
const config = JSON.parse(fs.readFileSync(fconfig));
const ukey = crypto.createECDH("secp256k1");
ukey.setPrivateKey(config.key, "base64");
const upub = ukey.getPublicKey("base64");

async function readMeta(fn) {
  let meta;
  let aesKey;
  if (fs.existsSync(fn)) {
    const data = await new Promise((resolve, reject) => {
      try {
        const input = fs.createReadStream(fn);
        const lines = [];
        let buf;
        let ndone = true;
        input.on("data", chunk => {
          if (buf) {
            buf = Buffer.concat([buf, chunk]);
          } else {
            buf = chunk;
          }
          const bline = buf.toString("utf8").split("\n");
          if (bline.length > 1) {
            buf = Buffer.from(bline.slice(-1)[0], "utf8");
            bline.slice(0, -1).forEach(bl => {
              if (ndone) {
                if (bl.length > 0) {
                  lines.push(bl);
                } else {
                  ndone = false;
                  input.close();
                  resolve(lines.join("\n"));
                }
              }
            });
            lines.push(...bline.slice(0, -1));
          }
        });
        input.on("end", () => {
          resolve(null);
        });
      } catch (err) {
        reject(err);
      }
    });
    meta = yaml.safeLoad(data);
    const ux = meta.users.filter(user => user.pub === upub)[0];
    if (!ux) {
      console.log("Dont have access to it");
      process.exit(1);
    }
    const aesd = crypto.createDecipheriv(
      "aes256",
      ukey.computeSecret(Buffer.from(meta.key, "base64")),
      Buffer.from(meta.key, "base64").slice(0, 16)
    );
    aesKey = Buffer.concat([
      aesd.update(Buffer.from(ux.enc, "base64")),
      aesd.final()
    ]);
  } else {
    const key = crypto.createECDH("secp256k1");
    key.generateKeys();
    aesKey = crypto.randomBytes(32);
    const user = {
      user: config.user,
      email: config.email,
      pub: ukey.getPublicKey("base64"),
      sig: config.sig
    };
    const aes = crypto.createCipheriv(
      "aes256",
      key.computeSecret(Buffer.from(user.pub, "base64")),
      key.getPublicKey().slice(0, 16)
    );
    user.enc = Buffer.concat([aes.update(aesKey), aes.final()]).toString(
      "base64"
    );
    const keyEncoder = new KeyEncoder("secp256k1");
    const pkeyPem = keyEncoder.encodePrivate(key.getPrivateKey(), "raw", "pem");
    const sig = crypto.createSign("sha512");
    sig.update(JSON.stringify([user]));
    meta = {
      key: key.getPublicKey("base64"),
      users: [user],
      sig: sig.sign(pkeyPem, "base64")
    };
  }
  return { meta, aesKey };
}

async function decrypt(fn, meta, aesKey, output) {
  const aesd = crypto.createDecipheriv(
    "aes256",
    aesKey,
    Buffer.from(meta.key, "base64").slice(0, 16)
  );
  const data = await new Promise((resolve, reject) => {
    try {
      const input = fs.createReadStream(fn);
      let buf;
      let data = false;
      input.on("data", chunk => {
        if (buf) {
          buf = Buffer.concat([buf, chunk]);
        } else {
          buf = chunk;
        }
        const bline = buf.toString("utf8").split("\n");
        if (bline.length > 1) {
          buf = Buffer.from(bline.slice(-1)[0], "utf8");
          bline.slice(0, -1).forEach(bl => {
            if (data) {
              output.write(
                aesd.update(Buffer.from(bl, "base64")).toString("utf8")
              );
            } else {
              if (bl.length === 0) {
                data = true;
              }
            }
          });
        }
      });
      input.on("end", () => {
        output.write(aesd.update(buf).toString("utf8"));
        output.write(aesd.final().toString("utf8"));
        resolve();
      });
    } catch (err) {
      reject(err);
    }
  });
}

program
  .command("init [user] [email]")
  .description("create asymetric key")
  .option("-f, --force", "Overwrite existing config")
  .action((user, email, options) => {
    if (fs.existsSync(fconfig) && !options.force) {
      console.log("config already exist. use --force to overwrite");
      process.exit(1);
    }
    const key = crypto.createECDH("secp256k1");
    key.generateKeys();

    const keyEncoder = new KeyEncoder("secp256k1");
    const pkeyPem = keyEncoder.encodePrivate(key.getPrivateKey(), "raw", "pem");
    const sig = crypto.createSign("sha512");
    sig.update(
      JSON.stringify({ user, email, pub: key.getPublicKey("base64") })
    );
    const config = {
      user,
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
    const invite = {
      user: config.user,
      email: config.email,
      pub: ukey.getPublicKey("base64"),
      sig: config.sig
    };
    console.log(JSON.stringify(invite, undefined, 2));
  });

program
  .command("user file")
  .description("edit file users")
  .action(async fn => {
    if (!fs.existsSync(fn)) {
      console.log("file ${fn}");
      process.exit(1);
    }
    if (!fs.existsSync(fconfig)) {
      console.log("config not exist. init first");
      process.exit(1);
    }
    const config = JSON.parse(fs.readFileSync(fconfig));
    const ukey = crypto.createECDH("secp256k1");
    ukey.setPrivateKey(config.key, "base64");
    const ftmp = path.join(
      path.dirname(fn),
      path.basename(fn) + ".encryptor.json"
    );
    const rl = readline.createInterface({
      input: fs.createReadStream(fn),
      crlfDelay: Infinity
    });
    let state = 0;
    const metas = [];
    const meta = await new Promise((resolve, reject) => {
      rl.on("line", line => {
        if (state === 0) {
          if (line.length === 0) {
            state = 1;
            resolve(yaml.safeLoad(metas.join("\n")));
            rl.close();
          } else {
            metas.push(line);
          }
        }
      });
    });
    fs.writeFileSync(
      ftmp,
      JSON.stringify(
        meta.users.map(u => ({
          user: u.user,
          email: u.email,
          pub: u.pub,
          sig: u.sig
        })),
        undefined,
        2
      )
    );
    execSync(`code --wait ${ftmp}`);
    fs.unlinkSync(ftmp);
  });

program
  .command("cat [file]")
  .description("view encrypted file")
  .action(async fn => {
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    const { meta, aesKey } = await readMeta(fn);
    await decrypt(fn, meta, aesKey, process.stdout);
    console.log();
  });

program
  .command("edit [file]")
  .description("edit encrypted file")
  .action(async fn => {
    const { meta, aesKey } = await readMeta(fn);
    const ftmp = path.join(
      path.dirname(fn),
      path.basename(fn, path.extname(fn)) + ".encryptor" + path.extname(fn)
    );
    execSync(`${config.editor} ${ftmp}`);

    const aes = crypto.createCipheriv(
      "aes256",
      aesKey,
      Buffer.from(meta.key, "base64").slice(0, 16)
    );

    const input = fs.createReadStream(ftmp, { highWaterMark: 1024 });
    const output = fs.createWriteStream(fn);

    output.write(yaml.safeDump(meta));
    output.write("\n");

    await new Promise((resolve, reject) => {
      input.on("data", chunk => {
        output.write(aes.update(chunk).toString("base64"));
        output.write("\n");
      });
      input.on("end", () => {
        output.write(aes.final().toString("base64"));
        output.write("\n");
        resolve();
      });
    });
    fs.unlinkSync(ftmp);
  });

program.parse(process.argv);
