package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.token.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakIntrospectionServiceTest {

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private KeycloakConfigService utilsConfigService;

    @Mock
    private KeycloakOidcClient keycloakOidcClient;

    @InjectMocks
    private KeycloakIntrospectionService keycloakIntrospectionService;

    private String realm;
    private String clientId;
    private String clientSecret;
    private String keycloakRealm;
    private RefreshTokenRequest tokenRequest;

    @BeforeEach
    void setUp() {
        realm = "test-tenant";
        clientId = "test-client";
        clientSecret = "test-secret";
        keycloakRealm = "mapped-realm";
        tokenRequest = new RefreshTokenRequest("mock-token-123");

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

        when(keycloakOidcClient.createBasicAuthHeaders(clientId, clientSecret)).thenReturn(new HttpHeaders());

        when(keycloakOidcClient.postRequest(
                eq(keycloakRealm),
                eq("token/introspect"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(Map.class)
        )).thenReturn(mockResponse);

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
    @DisplayName("Debería propagar ResponseStatusException si ocurre en el cliente OIDC")
    void introspectToken_shouldPropagateResponseStatusException_onOidcClientFailure() {
        when(keycloakOidcClient.createBasicAuthHeaders(clientId, clientSecret)).thenReturn(new HttpHeaders());

        when(keycloakOidcClient.postRequest(
                anyString(),
                eq("token/introspect"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(Map.class)
        )).thenThrow(new ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST, "Invalid token"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            keycloakIntrospectionService.introspectToken(realm, tokenRequest, clientId);
        });

        assertEquals("400 BAD_REQUEST \"Invalid token\"", exception.getMessage());
    }
}
