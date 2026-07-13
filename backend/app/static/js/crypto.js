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