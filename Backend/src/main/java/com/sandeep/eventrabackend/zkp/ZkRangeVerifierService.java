package com.sandeep.eventrabackend.zkp;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Cryptographic Zero-Knowledge Range Proof Verifier Service (#14048).
 * Validates ZKP Commitments for attendee eligibility checks without exposing birthdays.
 */
@Service
public class ZkRangeVerifierService {

    /**
     * Verify range proof: H(Age + Salt) matches the committed value and the
     * claimed value lies within {@code [minInclusive, maxInclusive]}.
     */
    public boolean verifyRangeProof(String commitment, String proofValue, String salt,
            int minInclusive, int maxInclusive) {
        if (commitment == null || proofValue == null || salt == null) {
            return false;
        }

        try {
            int age = Integer.parseInt(proofValue.trim());
            if (age < minInclusive || age > maxInclusive) {
                return false;
            }

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest((proofValue + salt).getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return MessageDigest.isEqual(
                    commitment.getBytes(StandardCharsets.US_ASCII),
                    hexString.toString().getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            return false;
        }
    }
}
