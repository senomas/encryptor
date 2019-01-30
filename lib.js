const debug = require("debug")("encryptor");

const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const KeyEncoder = require("key-encoder");
const yaml = require("js-yaml");
const streamBuffers = require("stream-buffers");

const keyEncoder = new KeyEncoder("secp256k1");
const fcontacts = path.join(os.homedir(), ".seno-encryptor-contacts");
const fcontact = path.join(os.homedir(), ".seno-encryptor-contact.json");

function getConfig(options = {}) {
  const fconfig = options.config
    ? options.config
    : path.join(os.homedir(), ".seno-encryptor");
  if (!fs.existsSync(fconfig)) {
    console.log("config not exist. init first");
    process.exit(1);
  }
  const config = JSON.parse(fs.readFileSync(fconfig));
  const ukey = crypto.createECDH("secp256k1");
  ukey.setPrivateKey(config.key, "base64");
  const upub = ukey.getPublicKey("base64");
  return { config, ukey, upub };
}

async function readMeta(fn, options) {
  let meta;
  let aesKey;
  const { config, ukey, upub } = getConfig(options);
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
        debug(err);
        reject(err);
      }
    });
    meta = yaml.safeLoad(data);
    const pubPem = keyEncoder.encodePublic(
      Buffer.from(meta.key, "base64"),
      "raw",
      "pem"
    );
    const sig = crypto.createVerify("sha512");
    sig.update(JSON.stringify(meta.users));
    if (!sig.verify(pubPem, Buffer.from(meta.sig, "base64"))) {
      throw new Error("Invalid meta signature");
    }
    meta.users.forEach(user => {
      const pubPem = keyEncoder.encodePublic(
        Buffer.from(user.pub, "base64"),
        "raw",
        "pem"
      );
      const sig = crypto.createVerify("sha512");
      const ux = Object.assign({}, user);
      delete ux.sig;
      delete ux.enc;
      sig.update(JSON.stringify(ux));
      if (!sig.verify(pubPem, Buffer.from(user.sig, "base64"))) {
        debug(ux);
        throw new Error(`Invalid user signature for ${user.email}`);
      }
    });
    const ux = meta.users.filter(user => user.pub === upub)[0];
    if (!ux) {
      throw new Error("Dont have access to it");
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

async function updateUser(meta, users, options) {
  const { config, ukey, upub } = getConfig(options);
  const key = crypto.createECDH("secp256k1");
  key.generateKeys();
  aesKey = crypto.randomBytes(32);
  users.forEach(user => {
    const pubPem = keyEncoder.encodePublic(
      Buffer.from(user.pub, "base64"),
      "raw",
      "pem"
    );
    const sig = crypto.createVerify("sha512");
    const ux = Object.assign({}, user);
    delete ux.sig;
    delete ux.enc;
    sig.update(JSON.stringify(ux));
    if (!sig.verify(pubPem, Buffer.from(user.sig, "base64"))) {
      debug(ux);
      throw new Error(`Invalid user signature for ${user.email}`);
    }
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

async function readEncrypted(fn, options = {}) {
  const { meta, aesKey } = await readMeta(fn, options);
  const buf = new streamBuffers.WritableStreamBuffer();
  await decrypt(fn, meta, aesKey, buf);
  return buf.getContentsAsString("utf8");
}

async function writeEncrypted(fn, input, options = {}) {
  const { meta, aesKey } = await readMeta(fn, options);
  const aes = crypto.createCipheriv(
    "aes256",
    aesKey,
    Buffer.from(meta.key, "base64").slice(0, 16)
  );

  const output = fs.createWriteStream(fn);
  output.write("=== BEGIN SENO-ENCRYPTOR ===\n");
  output.write("SENO-ENCRYPTOR # https://github.com/senomas/encryptor\n");
  output.write(
    yaml
      .safeDump(meta)
      .split("\n")
      .map(ln => "SENO-ENCRYPTOR " + ln)
      .join("\n")
  );
  output.write("\n=== END SENO-ENCRYPTOR ===\n");

  for (
    let i = 0, il = input.length, chunkSize = 1024;
    i < il;
    i = i + chunkSize
  ) {
    const chunk = input.substr(i, chunkSize);
    output.write(aes.update(chunk).toString("base64"));
    output.write("\n");
  }
  output.write(aes.final().toString("base64"));
  output.write("\n");
  output.close();
  await waitStreamClose(output);
}

async function decrypt(fn, meta, aesKey, output) {
  if (!fs.existsSync(fn)) {
    return;
  }
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
  output.write("SENO-ENCRYPTOR # https://github.com/senomas/encryptor\n");
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

function getContacts() {
  if (fs.existsSync(fcontacts)) {
    return JSON.parse(fs.readFileSync(fcontacts));
  }
  return {};
}

function saveContacts(contacts) {
  fs.writeFileSync(fcontacts, JSON.stringify(contacts, undefined, 2));
}

module.exports = {
  getConfig,
  readMeta,
  updateUser,
  encrypt,
  decrypt,
  waitStreamClose,
  readEncrypted,
  writeEncrypted,
  getContacts,
  saveContacts,
  keyEncoder,
  fcontacts,
  fcontact
};
