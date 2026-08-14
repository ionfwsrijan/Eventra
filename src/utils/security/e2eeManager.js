/**
 * End-to-End Encryption (E2EE) Manager using Web Crypto API / SubtleCrypto
 * Supports AES-GCM-256 encryption and ECDH key derivation.
 *
 * Security note: encryption is only claimed when a real recipient public
 * key (ECDH P-256 JWK) is provided. With no valid key, the message is NOT
 * encrypted and the returned blob marks itself as such (`isEncrypted: false`)
 * so callers can never mistake base64 for ciphertext.
 */

const getCrypto = () => {
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  if (typeof window !== "undefined" && window.crypto?.subtle) {
    return window.crypto;
  }
  return null;
};

const bytesToBase64 = (bytes) => {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const base64ToBytes = (b64) => {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

export async function generateE2EEKeyPair() {
  const cryptoApi = getCrypto();
  if (cryptoApi) {
    try {
      const keyPair = await cryptoApi.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"]
      );
      return {
        publicKeyJwk: await cryptoApi.subtle.exportKey("jwk", keyPair.publicKey),
        privateKeyJwk: await cryptoApi.subtle.exportKey("jwk", keyPair.privateKey),
      };
    } catch (e) {
      console.warn("[E2EEManager] SubtleCrypto ECDH generation failed:", e);
    }
  }

  // No Web Crypto available: there is nothing to encrypt with.
  return { publicKeyJwk: null, privateKeyJwk: null };
}

export async function encryptE2EEMessage(plaintext, recipientPublicKeyJwk) {
  if (!plaintext) {
    return { ciphertext: null, isEncrypted: false, timestamp: Date.now() };
  }

  const cryptoApi = getCrypto();
  const hasRecipientKey =
    recipientPublicKeyJwk &&
    typeof recipientPublicKeyJwk === "object" &&
    recipientPublicKeyJwk.kty &&
    cryptoApi;

  if (hasRecipientKey) {
    try {
      const recipientKey = await cryptoApi.subtle.importKey(
        "jwk",
        recipientPublicKeyJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );
      const ephemeral = await cryptoApi.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
      const shared = await cryptoApi.subtle.deriveBits(
        { name: "ECDH", public: recipientKey },
        ephemeral.privateKey,
        256
      );
      const aesKey = await cryptoApi.subtle.importKey(
        "raw",
        shared,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const iv = cryptoApi.getRandomValues(new Uint8Array(12));
      const ciphertext = await cryptoApi.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        new TextEncoder().encode(plaintext)
      );
      const ephemeralPublicKey = await cryptoApi.subtle.exportKey("jwk", ephemeral.publicKey);

      return {
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
        iv: bytesToBase64(iv),
        ephemeralPublicKey,
        recipientPublicKeyId: recipientPublicKeyJwk.kid || null,
        timestamp: Date.now(),
        isEncrypted: true,
      };
    } catch (err) {
      console.warn("[E2EEManager] Encryption failed:", err);
    }
  }

  // No usable recipient public key (or encryption failed): the message
  // cannot be encrypted. Report the honest state instead of faking it.
  return {
    ciphertext: null,
    isEncrypted: false,
    timestamp: Date.now(),
  };
}

export async function decryptE2EEMessage(encryptedBlob, recipientPrivateKeyJwk) {
  if (
    !encryptedBlob ||
    encryptedBlob.isEncrypted !== true ||
    !encryptedBlob.ciphertext
  ) {
    return "";
  }

  const cryptoApi = getCrypto();
  if (!cryptoApi || !recipientPrivateKeyJwk || !encryptedBlob.ephemeralPublicKey) {
    console.warn(
      "[E2EEManager] Decryption requires the recipient private key and the sender ephemeral public key"
    );
    return "";
  }

  try {
    const recipientKey = await cryptoApi.subtle.importKey(
      "jwk",
      recipientPrivateKeyJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
    const ephemeralPublic = await cryptoApi.subtle.importKey(
      "jwk",
      encryptedBlob.ephemeralPublicKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const shared = await cryptoApi.subtle.deriveBits(
      { name: "ECDH", public: ephemeralPublic },
      recipientKey,
      256
    );
    const aesKey = await cryptoApi.subtle.importKey(
      "raw",
      shared,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const plaintext = await cryptoApi.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(encryptedBlob.iv) },
      aesKey,
      base64ToBytes(encryptedBlob.ciphertext)
    );
    return new TextDecoder().decode(plaintext);
  } catch (err) {
    console.error("[E2EEManager] Decryption failed:", err);
    return "[Decryption Error]";
  }
}
