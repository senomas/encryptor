const program = require("commander");
const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const stream = require("stream");
const KeyEncoder = require("key-encoder");
const fconfig = path.join(os.homedir(), ".seno-encryptor");
const execSync = require("child_process").execSync;
const yaml = require("js-yaml");
const readline = require("readline");

async function readMeta(fn) {
  const rl = readline.createInterface({
    input: fs.createReadStream(fn),
    crlfDelay: Infinity
  });
  const metas = [];
  return await new Promise((resolve, reject) => {
    rl.on("line", line => {
      if (line.length === 0) {
        resolve(yaml.safeLoad(metas.join("\n")));
        rl.close();
      } else {
        metas.push(line);
      }
    });
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
      key: key.getPrivateKey("base64")
    };
    fs.writeFileSync(fconfig, JSON.stringify(config, undefined, 2));
  });

program
  .command("invite")
  .description("create request command")
  .action(() => {
    if (!fs.existsSync(fconfig)) {
      console.log("config not exist. init first");
      process.exit(1);
    }
    const config = JSON.parse(fs.readFileSync(fconfig));
    const ukey = crypto.createECDH("secp256k1");
    ukey.setPrivateKey(config.key, "base64");
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
    if (!fs.existsSync(fconfig)) {
      console.log("config not exist. init first");
      process.exit(1);
    }
    const config = JSON.parse(fs.readFileSync(fconfig));
    const ukey = crypto.createECDH("secp256k1");
    ukey.setPrivateKey(config.key, "base64");
    const upub = ukey.getPublicKey("base64");
    const users = [];
    const ftmp = path.join(
      path.dirname(fn),
      path.basename(fn, path.extname(fn)) + ".encryptor" + path.extname(fn)
    );
    const meta = await readMeta(fn);
    const ux = meta.users.filter(user => user.pub === upub)[0];
    if (!ux) {
      console.log("Dont have access to it");
      process.exit(1);
    }
    let aesd = crypto.createDecipheriv(
      "aes256",
      ukey.computeSecret(Buffer.from(meta.key, "base64")),
      Buffer.from(meta.key, "base64").slice(0, 16)
    );
    const aesKey = Buffer.concat([
      aesd.update(Buffer.from(ux.enc, "base64")),
      aesd.final()
    ]);
    aesd = crypto.createDecipheriv(
      "aes256",
      aesKey,
      Buffer.from(meta.key, "base64").slice(0, 16)
    );
    let state = 0;
    const output = fs.createWriteStream(ftmp);
    const bufs = [];
    await new Promise(resolve => {
      const rl = readline.createInterface({
        input: fs.createReadStream(fn),
        crlfDelay: Infinity
      });
      rl.on("line", line => {
        if (state === 0) {
          if (line.length === 0) {
            state = 1;
          }
        } else {
          if (line.length > 0) {
            process.stdout.write(
              aesd.update(Buffer.from(line, "base64")).toString("utf8")
            );
          }
        }
      });
      rl.on("close", () => {
        process.stdout.write(aesd.final().toString("utf8"));
        resolve();
      });
    });
    console.log();
  });

program
  .command("edit [file]")
  .description("edit encrypted file")
  .action(async fn => {
    if (!fs.existsSync(fconfig)) {
      console.log("config not exist. init first");
      process.exit(1);
    }
    const config = JSON.parse(fs.readFileSync(fconfig));
    const ukey = crypto.createECDH("secp256k1");
    ukey.setPrivateKey(config.key, "base64");
    const upub = ukey.getPublicKey("base64");
    const ftmp = path.join(
      path.dirname(fn),
      path.basename(fn, path.extname(fn)) + ".encryptor" + path.extname(fn)
    );
    const { meta, aesKey } = await (async () => {
      if (fs.existsSync(fn)) {
        const meta = await readMeta(fn);
        const ux = meta.users.filter(user => user.pub === upub)[0];
        if (!ux) {
          console.log("Dont have access to it");
          process.exit(1);
        }
        let aesd = crypto.createDecipheriv(
          "aes256",
          ukey.computeSecret(Buffer.from(meta.key, "base64")),
          Buffer.from(meta.key, "base64").slice(0, 16)
        );
        const aesKey = Buffer.concat([
          aesd.update(Buffer.from(ux.enc, "base64")),
          aesd.final()
        ]);
        aesd = crypto.createDecipheriv(
          "aes256",
          aesKey,
          Buffer.from(meta.key, "base64").slice(0, 16)
        );
        const rl = readline.createInterface({
          input: fs.createReadStream(fn),
          crlfDelay: Infinity
        });
        let state = 0;
        const output = fs.createWriteStream(ftmp);
        await new Promise(resolve => {
          rl.on("line", line => {
            if (state === 0) {
              if (line.length === 0) {
                state = 1;
              }
            } else {
              if (line.length > 0) {
                output.write(
                  aesd.update(Buffer.from(line, "base64")).toString("utf8")
                );
              }
            }
          });
          rl.on("close", () => {
            output.write("\n\n-----CLOSE-----\n\n");
            output.write(aesd.final().toString("utf8"));
            resolve();
          });
        });
        return { meta, aesKey };
      } else {
        const key = crypto.createECDH("secp256k1");
        key.generateKeys();
        const aesKey = crypto.randomBytes(32);
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
        const pkeyPem = keyEncoder.encodePrivate(
          key.getPrivateKey(),
          "raw",
          "pem"
        );
        const sig = crypto.createSign("sha512");
        sig.update(JSON.stringify([user]));
        return {
          meta: {
            key: key.getPublicKey("base64"),
            users: [user],
            sig: sig.sign(pkeyPem, "base64")
          },
          aesKey
        };
      }
    })();

    // execSync(`code --wait ${ftmp}`);
    await new Promise((resolve, reject) => {
      const fi = fs.createReadStream("app.js");
      const fo = fs.createWriteStream(ftmp);
      fi.pipe(fo);
      fi.on("end", () => resolve());
    });

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
      input
        .pipe(
          new stream.Transform({
            transform(chunk, encoding, callback) {
              callback(null, aes.update(chunk).toString("base64") + "\n");
            }
          })
        )
        .pipe(output);
      input.on("close", () => {
        resolve()
      });
    });
    output.write(aes.final().toString("base64") + "\n");
    // fs.unlinkSync(ftmp);
  });

program.parse(process.argv);
