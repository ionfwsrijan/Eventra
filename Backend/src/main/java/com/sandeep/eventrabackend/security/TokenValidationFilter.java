package com.sandeep.eventrabackend.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Filter checking incoming token credentials signatures safely (#16468).
 */
@Component
public class TokenValidationFilter {

    private final OidcKeyCacheManager keyCacheManager;

    public TokenValidationFilter(OidcKeyCacheManager keyCacheManager) {
        this.keyCacheManager = keyCacheManager;
    }

    public boolean validateToken(String kid, String token) {
        String key = keyCacheManager.getPublicKey(kid);
        if (key == null) return false;
        try {
            Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}
