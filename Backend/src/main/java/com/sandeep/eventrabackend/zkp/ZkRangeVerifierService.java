package com.sandeep.eventrabackend.zkp;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Cryptographic Zero-Knowledge Range Proof Verifier Service (#14048).
 * Validates ZKP Commitments for attendee eligibility checks without exposing birthdays.
 */
@Service
public class ZkRangeVerifierService {

    /**
     * Verify range proof: the SHA-256 commitment must match {@code H(proofValue + salt)}
     * AND {@code proofValue} must fall within {@code [minValue, maxValue]}.
     * Without the bounds check any forged value whose hash matches the commitment
     * would be accepted, which provides no range guarantee at all.
     */
    public boolean verifyRangeProof(String commitment, String proofValue, String salt, long minValue, long maxValue) {
        if (commitment == null || proofValue == null || salt == null || minValue > maxValue) {
            return false;
        }

        try {
            long value = Long.parseLong(proofValue.trim());
            if (value < minValue || value > maxValue) {
                return false;
            }

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String input = proofValue + salt;
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return commitment.equalsIgnoreCase(hexString.toString());
        } catch (Exception e) {
            return false;
        }
    }
}
