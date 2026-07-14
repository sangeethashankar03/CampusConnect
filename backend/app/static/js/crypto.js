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
async function encryptMessage(plaintext, recipientEncryptionKeyPem, senderSigningPrivateKey) {
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
  const encAesKey = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientEncryptionKey,
    rawAesKey
  );

  const signature = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    senderSigningPrivateKey,
    ciphertext
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    nonce: arrayBufferToBase64(nonce),
    enc_aes_key: arrayBufferToBase64(encAesKey),
    signature: arrayBufferToBase64(signature),
  };
}