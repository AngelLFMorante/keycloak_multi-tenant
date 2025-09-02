package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.exception.KeycloakCommunicationException;
import com.example.keycloak.multitenant.model.token.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakIntrospectionServiceTest {

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private KeycloakConfigService utilsConfigService;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private KeycloakIntrospectionService keycloakIntrospectionService;

    private String realm;
    private String clientId;
    private String clientSecret;
    private RefreshTokenRequest tokenRequest;
    private String introspectUrl;
    private String keycloakRealm;

    @BeforeEach
    void setUp() {
        realm = "test-tenant";
        clientId = "test-client";
        clientSecret = "test-secret";
        keycloakRealm = "mapped-realm";
        tokenRequest = new RefreshTokenRequest("mock-token-123");
        introspectUrl = "http://localhost:8080/realms/mapped-realm/protocol/openid-connect/token/introspect";

        when(utilsConfigService.resolveRealm(realm)).thenReturn(keycloakRealm);
        Map<String, String> clientSecrets = new HashMap<>();
        clientSecrets.put(clientId, clientSecret);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
    }

    @Test
    @DisplayName("Debería realizar la introspección correctamente y devolver una respuesta activa")
    void introspectToken_shouldReturnActiveResponse_onSuccess() {
        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("active", true);
        mockResponse.put("sub", "user-id-123");
        mockResponse.put("scope", "read write");
        ResponseEntity<Map> responseEntity = new ResponseEntity<>(mockResponse, HttpStatus.OK);
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://localhost:8080");

        when(restTemplate.exchange(
                eq(introspectUrl),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenReturn(responseEntity);

        Map<String, Object> result = keycloakIntrospectionService.introspectToken(realm, tokenRequest, clientId);

        assertNotNull(result);
        assertEquals(true, result.get("active"));
        assertEquals("user-id-123", result.get("sub"));
    }

    @Test
    @DisplayName("Debería lanzar IllegalArgumentException si el secreto del cliente no se encuentra")
    void introspectToken_shouldThrowIllegalArgumentException_whenClientSecretIsNotFound() {
        when(keycloakProperties.getClientSecrets()).thenReturn(Collections.emptyMap());

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            keycloakIntrospectionService.introspectToken(realm, tokenRequest, clientId);
        });

        assertEquals("Client secret no encontrado para: " + clientId, exception.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar KeycloakCommunicationException en caso de error HTTP de cliente (4xx)")
    void introspectToken_shouldThrowKeycloakCommunicationException_onHttpClientError() {
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://localhost:8080");
        when(restTemplate.exchange(
                eq(introspectUrl),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Invalid token"));

        KeycloakCommunicationException exception = assertThrows(KeycloakCommunicationException.class, () -> {
            keycloakIntrospectionService.introspectToken(realm, tokenRequest, clientId);
        });

        assertEquals("Error del cliente al comunicarse con Keycloak: 400 Invalid token", exception.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar KeycloakCommunicationException en caso de error HTTP de servidor (5xx)")
    void introspectToken_shouldThrowKeycloakCommunicationException_onHttpServerError() {
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://localhost:8080");
        when(restTemplate.exchange(
                eq(introspectUrl),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenThrow(new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "Keycloak server error"));

        KeycloakCommunicationException exception = assertThrows(KeycloakCommunicationException.class, () -> {
            keycloakIntrospectionService.introspectToken(realm, tokenRequest, clientId);
        });

        assertEquals("Error del servidor de Keycloak: 500 Keycloak server error", exception.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar KeycloakCommunicationException en caso de error inesperado")
    void introspectToken_shouldThrowKeycloakCommunicationException_onUnexpectedError() {
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://localhost:8080");
        when(restTemplate.exchange(
                eq(introspectUrl),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenThrow(new RuntimeException("Connection refused"));

        KeycloakCommunicationException exception = assertThrows(KeycloakCommunicationException.class, () -> {
            keycloakIntrospectionService.introspectToken(realm, tokenRequest, clientId);
        });

        assertEquals("Error inesperado en la comunicación con Keycloak", exception.getMessage());
    }
}
