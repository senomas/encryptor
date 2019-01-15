const program = require('commander');

program
  .command('init [user] [email]')
  .description('create asymetric key')
  .action((user, email) => {
    console.log('create key for %s <%s>', user, email);
  });

program.parse(process.argv);