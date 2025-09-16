package com.example.keycloak.multitenant.service.utils;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakConfigServiceTest {

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private RestTemplate restTemplate;

    private KeycloakConfigService keycloakConfigService;

    private String publicRealm;
    private String keycloakRealm;
    private Map<String, String> realmMapping;
    private String authServerUrl;

    @BeforeEach
    void setUp() {
        publicRealm = "tenant1";
        keycloakRealm = "tenant1-realm";
        authServerUrl = "http://localhost:8080";

        realmMapping = new HashMap<>();
        realmMapping.put(publicRealm, keycloakRealm);

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);


        keycloakConfigService = new KeycloakConfigService(keycloakProperties, restTemplate);
    }

    @Test
    @DisplayName("Debería resolver el nombre del realm correctamente si el mapeo existe")
    void resolveRealm_shouldReturnKeycloakRealm_whenMappingExists() {
        String result = keycloakConfigService.resolveRealm(publicRealm);
        assertEquals(keycloakRealm, result);
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el mapeo del realm no existe")
    void resolveRealm_shouldThrowException_whenMappingDoesNotExist() {
        String nonExistentRealm = "non-existent-tenant";
        when(keycloakProperties.getRealmMapping()).thenReturn(new HashMap<>());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            keycloakConfigService.resolveRealm(nonExistentRealm);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertEquals("Realm " + nonExistentRealm + " no reconocido", exception.getReason());
    }


    @Test
    @DisplayName("Debería devolver la clave pública correctamente al obtenerla del JWKS")
    void getRealmPublicKey_shouldReturnPublicKey_whenKeyIsFound() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BigInteger modulus = ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getModulus();
        BigInteger publicExponent = ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getPublicExponent();

        String nStr = Base64.getUrlEncoder().withoutPadding().encodeToString(modulus.toByteArray());
        String eStr = Base64.getUrlEncoder().withoutPadding().encodeToString(publicExponent.toByteArray());
        String jwksUri = authServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs";
        Map<String, Object> oidcConfig = new HashMap<>();
        oidcConfig.put("jwks_uri", jwksUri);

        Map<String, Object> jwks = new HashMap<>();
        Map<String, Object> keyData = new HashMap<>();
        keyData.put("kty", "RSA");
        keyData.put("use", "sig");
        keyData.put("alg", "RS256");
        keyData.put("kid", "12345");
        keyData.put("n", nStr);
        keyData.put("e", eStr);
        jwks.put("keys", List.of(keyData));

        when(keycloakProperties.getAuthServerUrl()).thenReturn(authServerUrl);
        when(restTemplate.getForObject(
                eq(authServerUrl + "/realms/" + keycloakRealm + "/.well-known/openid-configuration"),
                eq(Map.class)
        )).thenReturn(oidcConfig);

        when(restTemplate.getForObject(eq(jwksUri), eq(Map.class))).thenReturn(jwks);

        Key publicKey = keycloakConfigService.getRealmPublicKey(publicRealm);

        assertNotNull(publicKey);
        assertTrue(publicKey instanceof java.security.interfaces.RSAPublicKey);
    }


    @Test
    @DisplayName("Debería lanzar ResponseStatusException si el JWKS no contiene una clave de firma")
    void getRealmPublicKey_shouldThrowException_whenNoSigningKeyFound() {
        Map<String, Object> oidcConfig = new HashMap<>();
        oidcConfig.put("jwks_uri", authServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs");

        Map<String, Object> jwks = new HashMap<>();
        Map<String, Object> keyData = new HashMap<>();
        keyData.put("kty", "RSA");
        keyData.put("use", "enc");
        jwks.put("keys", List.of(keyData));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            keycloakConfigService.getRealmPublicKey(publicRealm);
        });

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al obtener la clave pública para el realm: tenant1", exception.getReason());
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si la lista de claves en el JWKS está vacía")
    void getRealmPublicKey_shouldThrowException_whenKeysAreEmpty() {
        Map<String, Object> oidcConfig = new HashMap<>();
        oidcConfig.put("jwks_uri", authServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs");

        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", Collections.emptyList());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            keycloakConfigService.getRealmPublicKey(publicRealm);
        });

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertEquals("Error al obtener la clave pública para el realm: tenant1", exception.getReason());
    }
}
