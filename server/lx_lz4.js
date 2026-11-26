// lx_lz4.js —— 用 lz4js 复刻客户端 orange.lz4XorEncode，保证与 App 原生解码 100% 兼容。
// 用法：echo "<bon字节的hex>" | node lx_lz4.js  ->  stdout 输出 lz4XorEncode 后的 hex
const lz4 = require('lz4js');

function lz4XorEncode(e) {
  e = lz4.compress(e);            // lz4js 输出标准 LZ4 frame
  const t = 2 + Math.floor(248 * Math.random());
  let n = Math.min(e.length, 100);
  for (; --n >= 0; ) e[n] ^= t;
  e[0] = 112;                    // 'p'
  e[1] = 108;                    // 'l'
  e[2] = (170 & e[2]) | (t >> 7 & 1) << 6 | (t >> 6 & 1) << 4 | (t >> 5 & 1) << 2 | (t >> 4 & 1);
  e[3] = (170 & e[3]) | (t >> 3 & 1) << 6 | (t >> 2 & 1) << 4 | (t >> 1 & 1) << 2 | (t >> 0 & 1);
  return Buffer.from(e);
}

const chunks = [];
process.stdin.on('data', d => chunks.push(d));
process.stdin.on('end', () => {
  const hex = Buffer.concat(chunks).toString('utf8').trim();
  if (!hex) { process.exit(0); }
  try {
    const enc = lz4XorEncode(Buffer.from(hex, 'hex'));
    process.stdout.write(enc.toString('hex'));
  } catch (e) {
    process.stderr.write(String((e && e.stack) || e));
    process.exit(1);
  }
});
