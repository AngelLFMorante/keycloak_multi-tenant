package com.example.keycloak.multitenant.security;

import com.example.keycloak.multitenant.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import org.springframework.stereotype.Component;

@Component
public class PasswordTokenProvider {

    private final Key key;
    private final long expirationMillis;

    public PasswordTokenProvider(JwtProperties props) {
        this.key = Keys.hmacShaKeyFor(props.getSecret().getBytes());
        this.expirationMillis = props.getExpirationHours() * 3600_000;
    }

    public String generateToken(String userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userId)
                .claim("purpose", "set-password")
                .setIssuedAt(Date.from(now))
                .setExpiration(new Date(now.toEpochMilli() + expirationMillis))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateAndGetUserId(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}

