// Failure diagnostics only. An encrypted log never grants evidence or authority.
import assert from 'node:assert/strict';
import {constants,createPublicKey,createHash,createCipheriv,createDecipheriv,publicEncrypt,privateDecrypt,randomBytes} from 'node:crypto';
import {openSync,closeSync,fstatSync,readSync,lstatSync,constants as fsConstants} from 'node:fs';
const recipient=Object.freeze({spki_sha256:'b0c19d54f2aec9c8b6252354d8657e4bd85362cf17a238a8248679a818a8f08c'});
export const portfolioDiagnosticPublicKeySHA256=recipient.spki_sha256;
export const portfolioDiagnosticMaxLogBytes=4<<20;
export const portfolioDiagnosticMaxEnvelopeBytes=6<<20;
const phases=new Set(['SOURCE_PREFLIGHT','CREATE_PRIVATE_RESOURCES','PREPARE_FRESH_MODULES','OFFLINE_COMPILE','PRIVATE_STARTUP','ANALYTICS_SCHEMA','PREPARE_BROWSER_DEPENDENCIES','ACTUAL_ISSUED_PIPELINE_API_MODEL_BROWSER','OWNED_CLEANUP']);
const exact=(v,keys)=>{assert.ok(v&&typeof v==='object'&&!Array.isArray(v));assert.deepEqual(Object.keys(v).sort(),[...keys].sort());};
function context(v){exact(v,['source_tree','run_id','phase']);assert.match(v.source_tree,/^[a-f0-9]{40}$/);assert.match(v.run_id,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);assert.ok(phases.has(v.phase));return{source_tree:v.source_tree,run_id:v.run_id,phase:v.phase};}
export function portfolioDiagnosticFingerprint(publicPEM){
 assert.ok(Buffer.isBuffer(publicPEM)&&publicPEM.length>0&&publicPEM.length<=4096);assert.match(publicPEM.toString('ascii'),/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/);
 const key=createPublicKey(publicPEM);assert.equal(key.type,'public');assert.equal(key.asymmetricKeyType,'rsa');assert.equal(key.asymmetricKeyDetails.modulusLength,4096);assert.equal(key.asymmetricKeyDetails.publicExponent,65537n);
 return createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');
}
function header(ctx,fingerprint,bytes){assert.match(fingerprint,/^[a-f0-9]{64}$/);assert.ok(Number.isSafeInteger(bytes)&&bytes>0&&bytes<=portfolioDiagnosticMaxLogBytes);return{schema_version:'1',kind:'PRIVATE_CI_NATIVE_FAILURE_DIAGNOSTIC',content_cipher:'AES-256-GCM',key_wrap:'RSA-OAEP-SHA256',public_key_sha256:fingerprint,context:context(ctx),plaintext_bytes:bytes};}
const aad=h=>Buffer.from(JSON.stringify(h));
const encoded=(s,n,max=n)=>{assert.ok(typeof s==='string'&&s.length<=4*Math.ceil(max/3));const b=Buffer.from(s,'base64');assert.ok(b.length>=n&&b.length<=max);assert.equal(b.toString('base64'),s);return b;};
export function encryptPortfolioDiagnostic(raw,publicPEM,ctx){
 assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=portfolioDiagnosticMaxLogBytes);
 const fingerprint=portfolioDiagnosticFingerprint(publicPEM);
 const h=header(ctx,fingerprint,raw.length),bound=aad(h),key=randomBytes(32),nonce=randomBytes(12);
 try{const wrapped=publicEncrypt({key:publicPEM,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256',oaepLabel:bound},key);assert.equal(wrapped.length,512);
  const cipher=createCipheriv('aes-256-gcm',key,nonce,{authTagLength:16});cipher.setAAD(bound);const ciphertext=Buffer.concat([cipher.update(raw),cipher.final()]);
  return{...h,wrapped_key:wrapped.toString('base64'),nonce:nonce.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
 }finally{key.fill(0);}
}
export function encodePortfolioDiagnostic(value){const raw=Buffer.from(JSON.stringify(value)+'\n');assert.ok(raw.length>0&&raw.length<=portfolioDiagnosticMaxEnvelopeBytes);return raw;}
export function decodePortfolioDiagnostic(raw){assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=portfolioDiagnosticMaxEnvelopeBytes);const value=JSON.parse(raw);assert.ok(encodePortfolioDiagnostic(value).equals(raw),'Noncanonical diagnostic envelope refused');return value;}
export function decryptPortfolioDiagnostic(value,privateKey,expectedContext,expectedFingerprint=portfolioDiagnosticPublicKeySHA256){
 exact(value,['schema_version','kind','content_cipher','key_wrap','public_key_sha256','context','plaintext_bytes','wrapped_key','nonce','ciphertext','tag']);
 const h=header(value.context,value.public_key_sha256,value.plaintext_bytes);for(const k of ['schema_version','kind','content_cipher','key_wrap','public_key_sha256'])assert.equal(value[k],h[k]);assert.match(expectedFingerprint,/^[a-f0-9]{64}$/);assert.equal(value.public_key_sha256,expectedFingerprint);assert.deepEqual(context(value.context),context(expectedContext));
 assert.equal(privateKey.type,'private');assert.equal(privateKey.asymmetricKeyType,'rsa');assert.equal(privateKey.asymmetricKeyDetails.modulusLength,4096);
 const actualFingerprint=createHash('sha256').update(createPublicKey(privateKey).export({format:'der',type:'spki'})).digest('hex');assert.equal(actualFingerprint,value.public_key_sha256);
 const wrapped=encoded(value.wrapped_key,512),nonce=encoded(value.nonce,12),tag=encoded(value.tag,16),ciphertext=encoded(value.ciphertext,1,portfolioDiagnosticMaxLogBytes);assert.equal(ciphertext.length,value.plaintext_bytes);
 let key;try{const bound=aad(h);key=privateDecrypt({key:privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256',oaepLabel:bound},wrapped);assert.equal(key.length,32);const decipher=createDecipheriv('aes-256-gcm',key,nonce,{authTagLength:16});decipher.setAAD(bound);decipher.setAuthTag(tag);const chunks=[decipher.update(ciphertext),decipher.final()];return Buffer.concat(chunks);}finally{key?.fill(0);}
}
export function encryptPortfolioFailureFile(file,publicPEM,ctx){
 assert.equal(portfolioDiagnosticFingerprint(publicPEM),portfolioDiagnosticPublicKeySHA256,'Diagnostic recipient differs');
 const before=lstatSync(file);assert.ok(before.isFile()&&!before.isSymbolicLink()&&before.nlink===1&&before.size>0&&before.size<=portfolioDiagnosticMaxLogBytes);
 const fd=openSync(file,fsConstants.O_RDONLY|(fsConstants.O_NOFOLLOW??0));try{const opened=fstatSync(fd);assert.equal(opened.dev,before.dev);assert.equal(opened.ino,before.ino);assert.equal(opened.size,before.size);assert.ok(opened.isFile()&&opened.nlink===1);const raw=Buffer.alloc(opened.size);let offset=0;while(offset<raw.length){const n=readSync(fd,raw,offset,raw.length-offset,offset);assert.ok(n>0);offset+=n;}const after=fstatSync(fd);assert.equal(after.size,opened.size);assert.equal(after.mtimeMs,opened.mtimeMs);return encodePortfolioDiagnostic(encryptPortfolioDiagnostic(raw,publicPEM,ctx));}finally{closeSync(fd);}
}
