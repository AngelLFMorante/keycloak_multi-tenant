package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.ClientCredentialsTokenResponse;
import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.model.TokenValidationResponse;
import com.example.keycloak.multitenant.service.keycloak.KeycloakClientCredentialsService;
import com.example.keycloak.multitenant.service.keycloak.KeycloakIntrospectionService;
import com.example.keycloak.multitenant.service.utils.DataConversionUtilsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private KeycloakIntrospectionService introspectionService;

    @Mock
    private DataConversionUtilsService conversionUtilsService;

    @Mock
    private KeycloakClientCredentialsService keycloakClientCredentialsService;

    @InjectMocks
    private AuthService authService;

    private String realm;
    private String clientId;
    private RefreshTokenRequest tokenRequest;

    @BeforeEach
    void setUp() {
        realm = "test-realm";
        clientId = "test-client";
        tokenRequest = new RefreshTokenRequest("mock-refresh-token");
    }

    @Test
    @DisplayName("Debería validar un token exitosamente y mapear la respuesta")
    void validateToken_shouldReturnCorrectResponse_whenIntrospectionIsSuccessful() {
        // Arrange
        Map<String, Object> introspectionResult = new HashMap<>();
        introspectionResult.put("active", true);
        introspectionResult.put("token_type", "Bearer");
        introspectionResult.put("scope", "openid profile email");
        introspectionResult.put("sub", "user-1234");
        introspectionResult.put("session_state", "session-state-123");
        introspectionResult.put("aud", List.of("account"));
        introspectionResult.put("iss", "http://localhost:8080/realms/test-realm");
        introspectionResult.put("exp", 1672531199L);
        introspectionResult.put("azp", "test-client");

        when(introspectionService.introspectToken(eq(realm), eq(tokenRequest), eq(clientId)))
                .thenReturn(introspectionResult);
        when(conversionUtilsService.getSafeString(any(Map.class), eq("token_type"))).thenReturn("Bearer");
        when(conversionUtilsService.getSafeString(any(Map.class), eq("scope"))).thenReturn("openid profile email");
        when(conversionUtilsService.getSafeString(any(Map.class), eq("sub"))).thenReturn("user-1234");
        when(conversionUtilsService.getSafeString(any(Map.class), eq("session_state"))).thenReturn("session-state-123");
        when(conversionUtilsService.getSafeList(any(Map.class), eq("aud"))).thenReturn(List.of("account"));
        when(conversionUtilsService.getSafeString(any(Map.class), eq("iss"))).thenReturn("http://localhost:8080/realms/test-realm");
        when(conversionUtilsService.getSafeString(any(Map.class), eq("azp"))).thenReturn("test-client");
        when(conversionUtilsService.getSafeString(any(Map.class), eq("error_description"))).thenReturn(null);

        // Act
        TokenValidationResponse response = authService.validateToken(tokenRequest, realm, clientId);

        // Assert
        assertNotNull(response);
        assertEquals(true, response.active());
        assertEquals("user-1234", response.sub());
        assertEquals("Bearer", response.tokenType());
    }

    @Test
    @DisplayName("Debería obtener un token de credenciales de cliente exitosamente")
    void getClientCredentialsToken_shouldReturnToken_whenServiceCallIsSuccessful() {
        // Arrange
        ClientCredentialsTokenResponse mockTokenResponse = new ClientCredentialsTokenResponse(
                "mock-access-token", 3600, 0, "Bearer", "client.scope"
        );
        when(keycloakClientCredentialsService.obtainToken(eq("test-tenant"), eq(clientId)))
                .thenReturn(mockTokenResponse);

        // Act
        ClientCredentialsTokenResponse response = authService.getClientCredentialsToken("test-tenant", clientId);

        // Assert
        assertNotNull(response);
        assertEquals("mock-access-token", response.accessToken());
        assertEquals(3600, response.expiresIn());
    }
}
