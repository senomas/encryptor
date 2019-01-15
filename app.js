#!/usr/bin/env node

const debug = require('debug')('encryptor');

const program = require("commander");
const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const KeyEncoder = require("key-encoder");
const execSync = require("child_process").execSync;
const yaml = require("js-yaml");

const keyEncoder = new KeyEncoder("secp256k1");

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
        let state = 0;
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
              if (state === 0) {
                if (bl !== "=== BEGIN SENO-ENCRYPTOR ===") {
                  return reject(new Error("Invalid file signature"));
                }
                state = 1;
              } else if (state === 1) {
                if (bl === "=== END SENO-ENCRYPTOR ===") {
                  input.close();
                  resolve(lines.join("\n"));
                } else if (bl.startsWith("SENO-ENCRYPTOR ")) {
                  lines.push(bl.slice(15));
                } else {
                  return reject(new Error("Invalid file signature"));
                }
              }
            });
            lines.push(...bline.slice(0, -1));
          }
        });
        input.on("end", () => {
          return reject(new Error("Invalid file signature"));
        });
      } catch (err) {
        reject(err);
      }
    });
    meta = yaml.safeLoad(data);
    const pubPem = keyEncoder.encodePublic(Buffer.from(meta.key, "base64"), "raw", "pem");
    const sig = crypto.createVerify("sha512");
    sig.update(JSON.stringify(meta.users));
    if (!sig.verify(pubPem, Buffer.from(meta.sig, "base64"))) {
      throw new Error("Invalid meta signature");
    };
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

async function updateUser(meta, users) {
  const key = crypto.createECDH("secp256k1");
  key.generateKeys();
  aesKey = crypto.randomBytes(32);
  users.forEach(user => {
    const pubPem = keyEncoder.encodePublic(Buffer.from(user.pub, "base64"), "raw", "pem");
    const sig = crypto.createVerify("sha512");
    sig.update(
      JSON.stringify({ user: user.user, email: user.email, pub: user.pub })
    );
    if (!sig.verify(pubPem, Buffer.from(user.sig, "base64"))) {
      throw new Error(`Invalid user signature for ${JSON.stringify(user)}`);
    };
    const aes = crypto.createCipheriv(
      "aes256",
      key.computeSecret(Buffer.from(user.pub, "base64")),
      key.getPublicKey().slice(0, 16)
    );
    user.enc = Buffer.concat([aes.update(aesKey), aes.final()]).toString(
      "base64"
    );
  });
  const pkeyPem = keyEncoder.encodePrivate(key.getPrivateKey(), "raw", "pem");
  const sig = crypto.createSign("sha512");
  sig.update(JSON.stringify(users));
  meta = {
    key: key.getPublicKey("base64"),
    users,
    sig: sig.sign(pkeyPem, "base64")
  };
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
      let state = 0;
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
            if (state === 0) {
              if (bl !== "=== BEGIN SENO-ENCRYPTOR ===") {
                return reject(new Error("Invalid file signature"));
              }
              state = 1;
            } else if (state === 1) {
              if (bl === "=== END SENO-ENCRYPTOR ===") {
                state = 2;
              } else if (bl.startsWith("SENO-ENCRYPTOR ")) {
                // ignore
              } else {
                return reject(new Error("Invalid file signature"));
              }
            } else if (state === 2) {
              output.write(
                aesd.update(Buffer.from(bl, "base64")).toString("utf8")
              );
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

async function encrypt(fn, meta, aesKey, ftmp) {
  const aes = crypto.createCipheriv(
    "aes256",
    aesKey,
    Buffer.from(meta.key, "base64").slice(0, 16)
  );

  const input = fs.createReadStream(ftmp, { highWaterMark: 1024 });
  const output = fs.createWriteStream(fn);

  output.write("=== BEGIN SENO-ENCRYPTOR ===\n");
  output.write(
    yaml
      .safeDump(meta)
      .split("\n")
      .map(ln => "SENO-ENCRYPTOR " + ln)
      .join("\n")
  );
  output.write("\n=== END SENO-ENCRYPTOR ===\n");

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
}

async function waitStreamClose(stream) {
  return new Promise(resolve => {
    stream.on("close", () => {
      resolve();
    });
  });
}
program
  .command("init [user] [email]")
  .description("create asymetric key")
  .option("-f, --force", "Overwrite existing config")
  .action((user, email, options) => {
    if (!user || !email) {
      program.help();
      process.exit(1);
    }
    if (fs.existsSync(fconfig) && !options.force) {
      console.log("config already exist. use --force to overwrite");
      process.exit(1);
    }
    const key = crypto.createECDH("secp256k1");
    key.generateKeys();

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
  .command("user [file]")
  .description("edit file users")
  .action(async fn => {
    if (!fn) {
      program.help();
      process.exit(1);
    }
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    const ftmp = path.join(
      path.dirname(fn),
      path.basename(fn, path.extname(fn)) + ".encryptor" + path.extname(fn)
    );
    const ftmpMeta = path.join(
      path.dirname(fn),
      path.basename(fn) + ".encryptor.json"
    );
    try {
      const { meta, aesKey } = await readMeta(fn);
      const otmp = fs.createWriteStream(ftmp);
      await decrypt(fn, meta, aesKey, otmp);
      otmp.close();
      await waitStreamClose(otmp);
      fs.writeFileSync(
        ftmpMeta,
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
      execSync(`${config.editor} ${ftmpMeta}`);
      const users = JSON.parse(fs.readFileSync(ftmpMeta));
      const { meta: nmeta , aesKey: naesKey } = await updateUser(meta, users);
      await encrypt(fn, nmeta, naesKey, ftmp);
      fs.unlinkSync(ftmp);
      fs.unlinkSync(ftmpMeta);
    } catch (err) {
      debug(err);
      console.log(err.message);
      fs.unlinkSync(ftmp);
      fs.unlinkSync(ftmpMeta);
      process.exit(1);
    }
  });

program
  .command("cat [file]")
  .description("view encrypted file")
  .action(async fn => {
    if (!fn) {
      program.help();
      process.exit(1);
    }
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
  .command("edit [file]")
  .description("edit encrypted file")
  .action(async fn => {
    if (!fn) {
      program.help();
      process.exit(1);
    }
    const ftmp = path.join(
      path.dirname(fn),
      path.basename(fn, path.extname(fn)) + ".encryptor" + path.extname(fn)
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

program.on("command:*", () => {
  program.help();
  process.exit(1);
});

if (process.argv.length <= 2) {
  program.help();
  process.exit(1);
}

program.parse(process.argv);
