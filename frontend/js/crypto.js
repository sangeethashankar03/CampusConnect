async function deriveKekFromPassword(password, saltBytes) {
  const baseKey = await window.crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 210000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function wrapPrivateKeyWithKek(privateKey, kek) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, pkcs8);
  return arrayBufferToBase64(iv) + "." + arrayBufferToBase64(wrapped);
}

async function unwrapPrivateKeyWithKek(blob, kek, algo) {
  const [ivB64, dataB64] = blob.split(".");
  const iv = base64ToArrayBuffer(ivB64);
  const data = base64ToArrayBuffer(dataB64);
  const pkcs8 = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, kek, data);
  return window.crypto.subtle.importKey(
    "pkcs8", pkcs8, algo, true, algo.name === "RSA-OAEP" ? ["decrypt"] : ["sign"]
  );
}

async function setupNewKeysForPassword(password) {
  const encPair = await generateEncryptionKeyPair();
  const signPair = await generateSigningKeyPair();
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKekFromPassword(password, salt);

  return {
    encryption_key: await exportPublicKeyPem(encPair.publicKey),
    signing_key: await exportPublicKeyPem(signPair.publicKey),
    enc_private_key_blob: await wrapPrivateKeyWithKek(encPair.privateKey, kek),
    sign_private_key_blob: await wrapPrivateKeyWithKek(signPair.privateKey, kek),
    kdf_salt: arrayBufferToBase64(salt),
    encryptionPrivateKey: encPair.privateKey,
    signingPrivateKey: signPair.privateKey,
  };
}

async function recoverKeysForPassword(password, backup) {
  const salt = base64ToArrayBuffer(backup.kdf_salt);
  const kek = await deriveKekFromPassword(password, new Uint8Array(salt));
  const encryptionPrivateKey = await unwrapPrivateKeyWithKek(
    backup.enc_private_key_blob, kek, { name: "RSA-OAEP", hash: "SHA-256" }
  );
  const signingPrivateKey = await unwrapPrivateKeyWithKek(
    backup.sign_private_key_blob, kek, { name: "RSA-PSS", hash: "SHA-256" }
  );
  return { encryptionPrivateKey, signingPrivateKey };
}

async function generateEncryptionKeyPair() {
  return window.crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
}

async function generateSigningKeyPair() {
  return window.crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
}
async function exportPublicKeyPem(publicKey) {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  return arrayBufferToPem(spki, "PUBLIC KEY");
}

function arrayBufferToPem(buffer, label) {
  const base64 = arrayBufferToBase64(buffer);
  const lines = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN (PUBLIC|PRIVATE) KEY-----/, "")
    .replace(/-----END (PUBLIC|PRIVATE) KEY-----/, "")
    .replace(/\s/g, "");
  return base64ToArrayBuffer(b64);
}
async function importEncryptionPublicKey(pem) {
  return window.crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

async function importVerifyPublicKey(pem) {
  return window.crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(pem),
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["verify"]
  );
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function generateAesKey() {
  return window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}
async function decryptMessage(payload, recipientEncryptionPrivateKey, senderSigningKeyPem) {
  const ciphertext = base64ToArrayBuffer(payload.ciphertext);
  const nonce = base64ToArrayBuffer(payload.nonce);
  const signature = base64ToArrayBuffer(payload.signature);

  const senderVerifyKey = await importVerifyPublicKey(senderSigningKeyPem);
  const isValid = await window.crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    senderVerifyKey,
    signature,
    ciphertext
  );
  if (!isValid) {
    throw new Error("Signature verification failed — message may have been tampered with");
  }

  const encAesKey = base64ToArrayBuffer(payload.enc_aes_key);
  const rawAesKey = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    recipientEncryptionPrivateKey,
    encAesKey
  );
  const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);

  const plaintextBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey,
    ciphertext
  );
  return plaintextBuffer;
}
async function exportPrivateKeyPem(privateKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return arrayBufferToPem(pkcs8, "PRIVATE KEY");
}

async function importEncryptionPrivateKey(pem) {
  return window.crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

async function importSigningPrivateKey(pem) {
  return window.crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(pem),
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["sign"]
  );
}
async function encryptMessageDual(plaintext, recipientEncryptionKeyPem, senderEncryptionKeyPem, senderSigningPrivateKey) {
  const aesKey = await generateAesKey();
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));

  const encodedText = new TextEncoder().encode(plaintext);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey,
    encodedText
  );

  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

  const recipientEncryptionKey = await importEncryptionPublicKey(recipientEncryptionKeyPem);
  const encAesKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientEncryptionKey, rawAesKey);

  const senderEncryptionKey = await importEncryptionPublicKey(senderEncryptionKeyPem);
  const encAesKeySender = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, senderEncryptionKey, rawAesKey);

  const signature = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    senderSigningPrivateKey,
    ciphertext
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    nonce: arrayBufferToBase64(nonce),
    enc_aes_key: arrayBufferToBase64(encAesKey),
    enc_aes_key_sender: arrayBufferToBase64(encAesKeySender),
    signature: arrayBufferToBase64(signature),
  };
}

async function encryptFileDual(file, recipientEncryptionKeyPem, senderEncryptionKeyPem, senderSigningPrivateKey) {
  const arrayBuffer = await file.arrayBuffer();
  const aesKey = await generateAesKey();
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, arrayBuffer);
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

  const recipientEncryptionKey = await importEncryptionPublicKey(recipientEncryptionKeyPem);
  const encAesKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientEncryptionKey, rawAesKey);

  const senderEncryptionKey = await importEncryptionPublicKey(senderEncryptionKeyPem);
  const encAesKeySender = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, senderEncryptionKey, rawAesKey);

  const signature = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    senderSigningPrivateKey,
    ciphertext
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    nonce: arrayBufferToBase64(nonce),
    enc_aes_key: arrayBufferToBase64(encAesKey),
    enc_aes_key_sender: arrayBufferToBase64(encAesKeySender),
    signature: arrayBufferToBase64(signature),
  };
}

async function encryptFileForGroup(file, members) {
  const arrayBuffer = await file.arrayBuffer();
  const aesKey = await generateAesKey();
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, aesKey, arrayBuffer
  );
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

  const wrappedKeys = [];
  for (const member of members) {
    if (!member.encryption_key) continue;
    const pubKey = await importEncryptionPublicKey(member.encryption_key);
    const wrapped = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, rawAesKey);
    wrappedKeys.push({ user_id: member.user_id, wrapped_key: arrayBufferToBase64(wrapped) });
  }

  return {
    ciphertextBlob: new Blob([ciphertext]),
    nonce: arrayBufferToBase64(nonce),
    wrappedKeys,
  };
}

async function decryptGroupFile(download, myEncryptionPrivateKey) {
  const wrappedKey = base64ToArrayBuffer(download.wrapped_key);
  const rawAesKey = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" }, myEncryptionPrivateKey, wrappedKey
  );
  const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const nonce = base64ToArrayBuffer(download.nonce);
  const ciphertext = base64ToArrayBuffer(download.ciphertext);
  return window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(nonce) }, aesKey, ciphertext);
}

async function computeSafetyNumber(myEncryptionPublicPem, peerEncryptionPublicPem) {
  const [first, second] = [myEncryptionPublicPem, peerEncryptionPublicPem].sort();
  const combined = first + second;
  const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(combined));
  const bytes = new Uint8Array(digest);
  const groups = [];
  for (let i = 0; i < 10; i++) {
    groups.push(String(bytes[i] % 100).padStart(2, "0"));
  }
  return groups.join("").match(/.{1,5}/g).join("  ");
}


async function encryptGroupMessage(plaintext, members, mySigningPrivateKey) {
  const aesKey = await generateAesKey();
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(plaintext);
  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, encodedText);
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

  const wrappedKeys = [];
  for (const member of members) {
    if (!member.encryption_key) continue;
    const pubKey = await importEncryptionPublicKey(member.encryption_key);
    const wrapped = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, rawAesKey);
    wrappedKeys.push({ user_id: member.user_id, wrapped_key: arrayBufferToBase64(wrapped) });
  }

  const signature = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 }, mySigningPrivateKey, ciphertext
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    nonce: arrayBufferToBase64(nonce),
    signature: arrayBufferToBase64(signature),
    wrapped_keys: wrappedKeys,
  };
}

async function decryptGroupMessage(msg, myEncryptionPrivateKey, senderSigningKeyPem) {
  if (!msg.wrapped_key) {
    throw new Error("No key available for you on this message (sent before you joined?)");
  }
  const ciphertext = base64ToArrayBuffer(msg.ciphertext);
  const nonce = base64ToArrayBuffer(msg.nonce);
  const signature = base64ToArrayBuffer(msg.signature);

  const senderVerifyKey = await importVerifyPublicKey(senderSigningKeyPem);
  const isValid = await window.crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 }, senderVerifyKey, signature, ciphertext
  );
  if (!isValid) throw new Error("Signature verification failed — message may have been tampered with");

  const wrappedKey = base64ToArrayBuffer(msg.wrapped_key);
  const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myEncryptionPrivateKey, wrappedKey);
  const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintextBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(nonce) }, aesKey, ciphertext);
  return new TextDecoder().decode(plaintextBuffer);
}