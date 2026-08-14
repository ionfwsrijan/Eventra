package com.sandeep.eventrabackend.security;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Security-hardened TOTP Manager holding keys securely (#16505).
 * Implements RFC 6238 TOTP verification with HMAC-SHA1 and a +/- 1
 * time-step window.
 */
@Component
public class TotpManager {

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final long TIME_STEP_SECONDS = 30L;
    private static final int CODE_DIGITS = 6;
    private static final int CODE_MODULUS = 1_000_000;

    private final SecureRandom secureRandom = new SecureRandom();

    public String generateSecret() {
        byte[] buffer = new byte[20];
        secureRandom.nextBytes(buffer);
        return Base64.getEncoder().encodeToString(buffer);
    }

    /**
     * Verify a 6-digit TOTP code against the shared secret for the current
     * time step, allowing a +/- 1 step window for clock skew. Comparison is
     * constant-time. Returns {@code false} for null secrets and malformed codes.
     */
    public boolean verifyToken(String secret, int code) {
        if (secret == null || secret.isBlank() || code < 0 || code >= CODE_MODULUS) {
            return false;
        }
        byte[] key = decodeSecret(secret);
        if (key == null || key.length == 0) {
            return false;
        }

        long step = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;
        for (long s = step - 1; s <= step + 1; s++) {
            int expected = generateTotp(key, s);
            if (MessageDigest.isEqual(
                    String.valueOf(expected).getBytes(StandardCharsets.UTF_8),
                    String.valueOf(code).getBytes(StandardCharsets.UTF_8))) {
                return true;
            }
        }
        return false;
    }

    private byte[] decodeSecret(String secret) {
        String trimmed = secret.trim();
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            if (decoded.length > 0) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
            // fall through to base32
        }
        try {
            return base32Decode(trimmed);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private int generateTotp(byte[] key, long counter) {
        try {
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (counter & 0xFF);
                counter >>= 8;
            }
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            return binary % CODE_MODULUS;
        } catch (Exception e) {
            return -1;
        }
    }

    private static byte[] base32Decode(String value) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String clean = value.toUpperCase().replace("=", "");
        int length = clean.length();
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < length; i++) {
            int val = alphabet.indexOf(clean.charAt(i));
            if (val < 0) {
                throw new IllegalArgumentException("Invalid base32 character: " + clean.charAt(i));
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }
}
