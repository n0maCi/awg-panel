import bcrypt from 'bcryptjs';

const password = process.argv[2];

if (!password) {
  console.error('Использование: npm run password -- "ваш пароль"');
  process.exit(1);
}

console.log(await bcrypt.hash(password, 12));
