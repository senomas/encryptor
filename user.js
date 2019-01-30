const debug = require("debug")("encryptor");

const program = require("commander");
const fs = require("fs");
const path = require("path");
const execSync = require("child_process").execSync;

const {
  getConfig,
  readMeta,
  updateUser,
  encrypt,
  decrypt,
  waitStreamClose,
  getContacts
} = require("./lib");

program
  .command("show <file>")
  .option("--config <config>")
  .description("show user access")
  .action(async (fn, options) => {
    const { config } = getConfig(options);
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    try {
      const { meta } = await readMeta(fn);
      meta.users.forEach(user => {
        console.log(user.email);
        console.log(`   ${user.pub}`);
      });
    } catch (err) {
      debug(err);
      console.log(err.message);
      process.exit(1);
    }
  });

program
  .command("remove <file> <email>")
  .option("--config <config>")
  .description("remove user access")
  .action(async (fn, email, options) => {
    const { config } = getConfig(options);
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    const ftmp = path.join(
      path.dirname(fn),
      "." +
        path.basename(fn, path.extname(fn)) +
        ".encryptor" +
        path.extname(fn)
    );
    try {
      const { meta, aesKey } = await readMeta(fn);
      const users = meta.users.filter(user => {
        return user.email !== email;
      });
      const { meta: nmeta, aesKey: naesKey } = await updateUser(meta, users);
      const otmp = fs.createWriteStream(ftmp);
      await decrypt(fn, meta, aesKey, otmp);
      otmp.close();
      await waitStreamClose(otmp);
      await encrypt(fn, nmeta, naesKey, ftmp);
      fs.unlinkSync(ftmp);
    } catch (err) {
      debug(err);
      console.log(err.message);
      fs.unlinkSync(ftmp);
      process.exit(1);
    }
  });

program
  .command("add <file> <email>")
  .option("--config <config>")
  .description("add user access")
  .action(async (fn, email, options) => {
    const { config } = getConfig(options);
    if (!fs.existsSync(fn)) {
      console.log(`file ${fn} not exist`);
      process.exit(1);
    }
    const contacts = getContacts();
    const nuser = contacts[email];
    if (!nuser) {
      console.log(`User ${email} not exist in your contacts`);
      process.exit(1);
    }
    const ftmp = path.join(
      path.dirname(fn),
      "." +
        path.basename(fn, path.extname(fn)) +
        ".encryptor" +
        path.extname(fn)
    );
    try {
      const { meta, aesKey } = await readMeta(fn);
      const users = meta.users.filter(user => {
        return user.pub !== nuser.pub;
      });
      users.push(nuser);
      const { meta: nmeta, aesKey: naesKey } = await updateUser(meta, users);
      const otmp = fs.createWriteStream(ftmp);
      await decrypt(fn, meta, aesKey, otmp);
      otmp.close();
      await waitStreamClose(otmp);
      await encrypt(fn, nmeta, naesKey, ftmp);
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
