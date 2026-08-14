package com.sandeep.eventrabackend.security.passkey;

import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * FIDO2 Passkey Public Key Credential Repository.
 */
@Repository
public class PasskeyCredentialRepository {

    public static class PasskeyCredential {
        private String credentialId;
        private String userEmail;
        private String publicKeyPem;
        private long signCount;

        public PasskeyCredential() {}
        public PasskeyCredential(String credentialId, String userEmail, String publicKeyPem) {
            this.credentialId = credentialId;
            this.userEmail = userEmail;
            this.publicKeyPem = publicKeyPem;
            this.signCount = 0;
        }

        public String getCredentialId() { return credentialId; }
        public String getUserEmail() { return userEmail; }
        public String getPublicKeyPem() { return publicKeyPem; }
        public long getSignCount() { return signCount; }
        public void setSignCount(long signCount) { this.signCount = signCount; }
    }

    private final Map<String, PasskeyCredential> store = new ConcurrentHashMap<>();
    private final Map<String, String> credentialIdOwner = new ConcurrentHashMap<>();

    private static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private static String key(String userEmail, String credentialId) {
        return normalize(userEmail) + ":" + credentialId;
    }

    public void save(PasskeyCredential credential) {
        if (credential == null || credential.getCredentialId() == null || credential.getUserEmail() == null) {
            return;
        }
        String credentialId = credential.getCredentialId();
        String userEmail = normalize(credential.getUserEmail());
        if (!credentialIdOwner.containsKey(credentialId)) {
            String previousOwner = credentialIdOwner.putIfAbsent(credentialId, userEmail);
            if (previousOwner != null && !previousOwner.equals(userEmail)) {
                return;
            }
        } else if (!userEmail.equals(credentialIdOwner.get(credentialId))) {
            return;
        }
        store.put(key(userEmail, credentialId), credential);
    }

    public Optional<PasskeyCredential> findByUserEmailAndCredentialId(String userEmail, String credentialId) {
        if (userEmail == null || credentialId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(store.get(key(userEmail, credentialId)));
    }

    public List<PasskeyCredential> findByUserEmail(String userEmail) {
        if (userEmail == null) {
            return List.of();
        }
        String prefix = normalize(userEmail) + ":";
        return store.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith(prefix))
                .map(Map.Entry::getValue)
                .collect(Collectors.toList());
    }
}
