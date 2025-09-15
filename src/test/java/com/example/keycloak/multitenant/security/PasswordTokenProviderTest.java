package com.example.keycloak.multitenant.security;

import com.example.keycloak.multitenant.config.JwtProperties;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link PasswordTokenProvider}.
 * Verifica que el generador y validador de tokens se comporte correctamente.
 */
@ExtendWith(MockitoExtension.class)
class PasswordTokenProviderTest {

    private static final String SECRET_KEY = "un-secreto-para-pruebas-super-seguro-y-largo-256-bits";
    private static final long EXPIRATION_HOURS = 1L;
    private static final String USER_ID = "12345-abcde-67890-fghij";

    @Mock
    private JwtProperties jwtProperties;

    private PasswordTokenProvider tokenProvider;

    private Key testKey;

    @BeforeEach
    void setUp() {
        when(jwtProperties.getSecret()).thenReturn(SECRET_KEY);
        when(jwtProperties.getExpirationHours()).thenReturn(EXPIRATION_HOURS);

        this.testKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

        tokenProvider = new PasswordTokenProvider(jwtProperties);
    }

    @Test
    @DisplayName("Debería generar un token válido para el usuario")
    void generateToken_validUserId_shouldReturnValidToken() {
        String token = tokenProvider.generateToken(USER_ID);
        assertNotNull(token);

        String parsedUserId = Jwts.parserBuilder()
                .setSigningKey(testKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();

        assertEquals(USER_ID, parsedUserId);
    }

    @Test
    @DisplayName("Debería validar un token y devolver el ID del usuario")
    void validateAndGetUserId_validToken_shouldReturnUserId() {
        String token = Jwts.builder()
                .setSubject(USER_ID)
                .claim("purpose", "set-password")
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(new Date(Instant.now().toEpochMilli() + TimeUnit.HOURS.toMillis(EXPIRATION_HOURS)))
                .signWith(testKey)
                .compact();

        String userIdFromToken = tokenProvider.validateAndGetUserId(token);

        assertEquals(USER_ID, userIdFromToken);
    }

    @Test
    @DisplayName("No debería validar un token con firma incorrecta y debería lanzar una excepción")
    void validateAndGetUserId_invalidSignatureToken_shouldThrowException() {
        Key anotherKey = Keys.hmacShaKeyFor("otra-clave-secreta-diferente-para-la-firma-de-tokens".getBytes());
        String invalidToken = Jwts.builder()
                .setSubject(USER_ID)
                .claim("purpose", "set-password")
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(new Date(Instant.now().toEpochMilli() + TimeUnit.HOURS.toMillis(EXPIRATION_HOURS)))
                .signWith(anotherKey)
                .compact();

        assertThrows(SignatureException.class, () -> tokenProvider.validateAndGetUserId(invalidToken));
    }

    @Test
    @DisplayName("No debería validar un token expirado y debería lanzar una excepción")
    void validateAndGetUserId_expiredToken_shouldThrowException() {
        String expiredToken = Jwts.builder()
                .setSubject(USER_ID)
                .claim("purpose", "set-password")
                .setIssuedAt(new Date(Instant.now().minusSeconds(120).toEpochMilli()))
                .setExpiration(new Date(Instant.now().minusSeconds(60).toEpochMilli()))
                .signWith(testKey)
                .compact();

        assertThrows(ExpiredJwtException.class, () -> tokenProvider.validateAndGetUserId(expiredToken));
    }

    @Test
    @DisplayName("No debería validar un token mal formado y debería lanzar una excepción")
    void validateAndGetUserId_malformedToken_shouldThrowException() {
        String malformedToken = "esto.no.es-un-token-valido";
        assertThrows(MalformedJwtException.class, () -> tokenProvider.validateAndGetUserId(malformedToken));
    }
}
