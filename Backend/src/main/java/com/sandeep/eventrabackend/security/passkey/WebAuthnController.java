package com.sandeep.eventrabackend.security.passkey;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth/webauthn")
@Tag(name = "WebAuthn", description = "Passkey registration")
public class WebAuthnController {

    private static final int MAX_PENDING_CHALLENGES = 1000;
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(10);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final PasskeyCredentialRepository credentialRepository;

    /**
     * Server-side challenge store keyed by user email. Each challenge is
     * single-use, expires after {@link #CHALLENGE_TTL}, and the map is capped at
     * {@link #MAX_PENDING_CHALLENGES} entries so an attacker cannot grow it
     * without bound (#16258). A challenge is removed once a matching registration
     * is verified, so a client cannot replay a stale challenge against another
     * email.
     */
    private final ConcurrentHashMap<String, ChallengeEntry> pendingChallenges = new ConcurrentHashMap<>();

    public WebAuthnController(PasskeyCredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @PostMapping("/register-challenge")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "Generate a passkey registration challenge",
            description = "Issues a single-use, expiring challenge for the authenticated user. "
                    + "Authentication is required and the challenge is scoped to the caller's own account.",
            security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Map<String, Object>> generateRegisterChallenge(Authentication authentication) {
        String userEmail = authentication.getName();
        evictExpiredChallenges();
        if (pendingChallenges.size() >= MAX_PENDING_CHALLENGES) {
            throw new IllegalArgumentException("Too many pending passkey registrations. Please try again shortly.");
        }

        String challenge = UUID.randomUUID().toString();
        pendingChallenges.put(normalize(userEmail), new ChallengeEntry(challenge));

        Map<String, Object> response = new HashMap<>();
        response.put("challenge", challenge);
        response.put("rpName", "Eventra Platform");
        response.put("userEmail", userEmail);
        response.put("timeout", 60000);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-registration")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> verifyRegistration(
            @RequestBody Map<String, String> payload,
            Authentication authentication) {
        String credentialId = payload.get("credentialId");
        String userEmail = payload.get("userEmail");
        String publicKeyPem = payload.get("publicKey");
        String clientChallenge = payload.get("challenge");

        // The caller must be verifying for their own account — never a victim
        // email supplied in the body (#15366).
        if (authentication == null || !normalize(authentication.getName()).equals(normalize(userEmail))) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "You can only register passkeys for your own account.");
        }

        // The credential must be bound to the challenge we issued for this
        // email. A client-supplied challenge that was never stored (or that has
        // expired) is rejected.
        ChallengeEntry issued = pendingChallenges.get(normalize(userEmail));
        if (issued == null || isExpired(issued) || !issued.challenge.equals(clientChallenge)) {
            throw new IllegalArgumentException(
                    "Registration challenge is missing, expired or was not issued for this account. Please request a new challenge.");
        }

        // Reject empty / malformed credentials before they are persisted.
        if (credentialId == null || credentialId.isBlank()) {
            throw new IllegalArgumentException("credentialId is required.");
        }
        if (publicKeyPem == null || publicKeyPem.isBlank()
                || !publicKeyPem.contains("-----BEGIN") || !publicKeyPem.contains("PUBLIC KEY-----")) {
            throw new IllegalArgumentException("A valid PEM public key is required.");
        }

        String trimmedKey = publicKeyPem.trim();
        ECPublicKey publicKey = parsePublicKey(trimmedKey);
        verifyAssertionSignature(publicKey, issued.challenge, payload);

        PasskeyCredentialRepository.PasskeyCredential cred =
                new PasskeyCredentialRepository.PasskeyCredential(credentialId.trim(), userEmail, trimmedKey);
        credentialRepository.save(cred);

        // Single-use challenge — consume it so it cannot be replayed.
        pendingChallenges.remove(normalize(userEmail));

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "WebAuthn Passkey registered successfully.");
        return ResponseEntity.ok(response);
    }

    private ECPublicKey parsePublicKey(String pem) {
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(body);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("A valid EC P-256 public key is required.", e);
        }
    }

    private void verifyAssertionSignature(ECPublicKey publicKey, String issuedChallenge,
            Map<String, String> payload) {
        String clientDataJsonB64 = payload.get("clientDataJSON");
        String authenticatorDataB64 = payload.get("authenticatorData");
        String signatureB64 = payload.get("signature");
        if (clientDataJsonB64 == null || authenticatorDataB64 == null || signatureB64 == null) {
            throw new IllegalArgumentException(
                    "clientDataJSON, authenticatorData and signature are required to verify the passkey.");
        }
        try {
            String clientDataJson = new String(Base64.getUrlDecoder().decode(clientDataJsonB64),
                    StandardCharsets.UTF_8);
            Map<String, Object> clientData = OBJECT_MAPPER.readValue(
                    clientDataJson, new TypeReference<Map<String, Object>>() { });
            String clientType = (String) clientData.get("type");
            String clientChallenge = (String) clientData.get("challenge");
            String expectedChallenge = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(issuedChallenge.getBytes(StandardCharsets.UTF_8));
            if (clientType == null || !clientType.startsWith("webauthn.")) {
                throw new IllegalArgumentException("Invalid clientDataJSON type.");
            }
            if (clientChallenge == null || !expectedChallenge.equals(clientChallenge)) {
                throw new IllegalArgumentException(
                        "clientDataJSON challenge does not match the issued challenge.");
            }
            byte[] authenticatorData = Base64.getUrlDecoder().decode(authenticatorDataB64);
            byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
                    .digest(Base64.getUrlDecoder().decode(clientDataJsonB64));
            byte[] verificationData = new byte[authenticatorData.length + clientDataHash.length];
            System.arraycopy(authenticatorData, 0, verificationData, 0, authenticatorData.length);
            System.arraycopy(clientDataHash, 0, verificationData, authenticatorData.length,
                    clientDataHash.length);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(verificationData);
            if (!verifier.verify(Base64.getUrlDecoder().decode(signatureB64))) {
                throw new IllegalArgumentException("Passkey signature verification failed.");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Passkey verification failed: " + e.getMessage());
        }
    }

    private void evictExpiredChallenges() {
        Instant cutoff = Instant.now().minus(CHALLENGE_TTL);
        pendingChallenges.entrySet().removeIf(entry -> entry.getValue().createdAt.isBefore(cutoff));
    }

    private boolean isExpired(ChallengeEntry entry) {
        return entry.createdAt.isBefore(Instant.now().minus(CHALLENGE_TTL));
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase();
    }

    static final class ChallengeEntry {
        private final String challenge;
        private final Instant createdAt;

        ChallengeEntry(String challenge) {
            this(challenge, Instant.now());
        }

        ChallengeEntry(String challenge, Instant createdAt) {
            this.challenge = challenge;
            this.createdAt = createdAt;
        }
    }
}
