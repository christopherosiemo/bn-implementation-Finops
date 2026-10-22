import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { encryptBackup, authenticatedBackup, backupDigest } from '../lib/encrypted-backup.mjs';

test('encrypted recovery archive authenticates before restoring the exact original bytes', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'finops-backup-'));
  try {
    const file = path.join(directory, 'backup.enc'), key = randomBytes(32);
    const original = Buffer.from('native database bytes\0sensitive fixture value\n'.repeat(1000));
    const hash = await encryptBackup(Readable.from([original]), file, key);
    assert.equal(hash, await backupDigest(file));
    assert.ok(!readFileSync(file).includes(Buffer.from('sensitive fixture value')));
    if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600);
    let invoked = 0;
    const received = [];
    await authenticatedBackup(file, key, async () => {
      invoked++;
      const input = new Writable({ write(chunk, encoding, callback) { received.push(chunk); callback(); } });
      return { input, completed: new Promise(resolve => input.once('finish', resolve)) };
    });
    assert.equal(invoked, 1);
    assert.deepEqual(Buffer.concat(received), original);
    await assert.rejects(encryptBackup(Readable.from([original]), file, key), /EEXIST/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('wrong key, altered ciphertext, tag, format and truncated backups never invoke a restore consumer', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'finops-backup-negative-'));
  try {
    const original = path.join(directory, 'original.enc'), key = randomBytes(32);
    await encryptBackup(Readable.from([randomBytes(5000)]), original, key);
    const bytes = readFileSync(original);
    for (const mode of ['key', 'ciphertext', 'tag', 'header', 'truncate']) {
      const file = path.join(directory, `${mode}.enc`);
      const altered = Buffer.from(bytes);
      if (mode === 'ciphertext') altered[100] ^= 1;
      if (mode === 'tag') altered[altered.length - 1] ^= 1;
      if (mode === 'header') altered[0] ^= 1;
      writeFileSync(file, mode === 'truncate' ? altered.subarray(0, 10) : altered);
      let invoked = false;
      await assert.rejects(authenticatedBackup(file, mode === 'key' ? randomBytes(32) : key, async () => { invoked = true; }));
      assert.equal(invoked, false, mode);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('a backup changed after authentication is quarantined before delivering plaintext', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'finops-backup-race-'));
  try {
    const file = path.join(directory, 'archive.enc'), key = randomBytes(32);
    await encryptBackup(Readable.from([randomBytes(5000)]), file, key);
    let delivered = 0, aborted = false;
    await assert.rejects(authenticatedBackup(file, key, async () => {
      appendFileSync(file, Buffer.from([0]));
      const input = new Writable({ write(chunk, encoding, callback) { delivered += chunk.length; callback(); } });
      return { input, completed: Promise.resolve(), abort() { aborted = true; input.destroy(); } };
    }), /changed during authentication or recovery/);
    assert.equal(delivered, 0);
    assert.equal(aborted, true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('consumer failure aborts the disposable destination and cannot report recovery success', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'finops-backup-consumer-'));
  try {
    const file = path.join(directory, 'archive.enc'), key = randomBytes(32);
    await encryptBackup(Readable.from([randomBytes(5000)]), file, key);
    let aborted = false;
    await assert.rejects(authenticatedBackup(file, key, async () => {
      const input = new Writable({ write(chunk, encoding, callback) { callback(new Error('Isolated consumer failed')); } });
      return { input, completed: new Promise((resolve, reject) => { input.once('finish', resolve); input.once('error', reject); }), abort() { aborted = true; input.destroy(); } };
    }), /Isolated consumer failed/);
    assert.equal(aborted, true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
