// Local recovery tooling. Plaintext database archives are never written to the
// host filesystem. Authentication is completed before any restore consumer runs.
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, openSync, closeSync, fstatSync, readSync, appendFileSync, chmodSync } from 'node:fs';
import { Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGzip, createGunzip } from 'node:zlib';

const magic = Buffer.from('FINOPS-PG-BACKUP-V1\n');
const headerSize = magic.length + 12;
const maximumEncryptedBytes = 8 * 1024 ** 3;
const maximumPlainBytes = 16 * 1024 ** 3;
function limit(maximum) {
  let size = 0;
  return new Transform({ transform(chunk, encoding, callback) {
    size += chunk.length;
    callback(size > maximum ? new Error('Backup size exceeds the local recovery bound') : null, chunk);
  } });
}
function discard() { return new Writable({ write(chunk, encoding, callback) { callback(); } }); }
function validateKey(key) { assert.ok(Buffer.isBuffer(key) && key.length === 32, 'A 256-bit recovery key is required'); }

export async function encryptBackup(input, filename, key) {
  validateKey(key);
  const header = Buffer.concat([magic, randomBytes(12)]);
  const cipher = createCipheriv('aes-256-gcm', key, header.subarray(magic.length));
  cipher.setAAD(header);
  // Exclusive creation prevents replacing an earlier backup or following an
  // existing symlink. The key is managed separately by the caller.
  const output = createWriteStream(filename, { flags: 'wx', mode: 0o600 });
  output.write(header);
  await pipeline(input, limit(maximumPlainBytes), createGzip(), cipher, limit(maximumEncryptedBytes - headerSize - 16), output);
  appendFileSync(filename, cipher.getAuthTag());
  chmodSync(filename, 0o600);
  return backupDigest(filename);
}
export async function backupDigest(filename) {
  const digest = createHash('sha256');
  await pipeline(createReadStream(filename), limit(maximumEncryptedBytes), new Writable({ write(chunk, encoding, callback) { digest.update(chunk); callback(); } }));
  return digest.digest('hex');
}

// The verified descriptor remains open across both passes so replacing the
// pathname cannot switch which archive is restored. Restore consumers must be
// isolated disposable destinations; authentication/consumer errors leave them
// quarantined and may never be treated as a successful restore.
export async function authenticatedBackup(filename, key, consume) {
  validateKey(key);
  const fd = openSync(filename, 'r');
  try {
    const information = fstatSync(fd, { bigint: true });
    assert.ok(information.isFile() && information.size > BigInt(headerSize + 16) && information.size <= BigInt(maximumEncryptedBytes), 'A bounded encrypted backup is required');
    const size = Number(information.size);
    const stable = () => {
      const current = fstatSync(fd, { bigint: true });
      for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) assert.equal(current[field], information[field], 'Encrypted backup changed during authentication or recovery');
    };
    const header = Buffer.alloc(headerSize), tag = Buffer.alloc(16);
    assert.equal(readSync(fd, header, 0, header.length, 0), header.length);
    assert.ok(header.subarray(0, magic.length).equals(magic), 'Unsupported backup format');
    assert.equal(readSync(fd, tag, 0, tag.length, size - tag.length), tag.length);
    const decrypt = () => {
      const cipher = createDecipheriv('aes-256-gcm', key, header.subarray(magic.length));
      cipher.setAAD(header);
      cipher.setAuthTag(tag);
      return cipher;
    };
    const ciphertext = () => createReadStream(filename, { fd, start: headerSize, end: size - 17, autoClose: false });
    // No tar/restore process exists until complete authentication succeeds.
    await pipeline(ciphertext(), decrypt(), discard());
    stable();
    if (consume) {
      const consumer = await consume();
      assert.ok(consumer?.input && consumer?.completed, 'A bounded isolated restore consumer is required');
      try {
        stable();
        await Promise.all([pipeline(ciphertext(), decrypt(), createGunzip(), limit(maximumPlainBytes), consumer.input), consumer.completed]);
        stable();
      } catch (error) {
        consumer.abort?.();
        throw error;
      }
    }
  } finally { closeSync(fd); }
}
