package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.token.ClientCredentialsTokenResponse;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakClientCredentialsServiceTest {

    @Mock
    private KeycloakConfigService utilsConfigService;

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private KeycloakOidcClient keycloakOidcClient;

    @InjectMocks
    private KeycloakClientCredentialsService keycloakClientCredentialsService;

    private String tenant;
    private String clientId;
    private String realm;
    private String clientSecret;

    @BeforeEach
    void setUp() {
        tenant = "testTenant";
        clientId = "testClient";
        realm = "test-realm";
        clientSecret = "test-secret";

        when(utilsConfigService.resolveRealm(tenant)).thenReturn(realm);

        Map<String, String> clientSecrets = new HashMap<>();
        clientSecrets.put(clientId, clientSecret);
        when(keycloakProperties.getClientSecrets()).thenReturn(clientSecrets);
    }

    @Test
    @DisplayName("Debería obtener un token correctamente con credenciales de cliente válidas")
    void obtainToken_shouldReturnToken_whenCredentialsAreValid() {
        ClientCredentialsTokenResponse expectedResponse = new ClientCredentialsTokenResponse(
                "mock_access_token", 3600, 0, "scope-1", "test-scope"
        );

        when(keycloakOidcClient.postRequest(
                eq(realm),
                eq("token"),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(ClientCredentialsTokenResponse.class)
        )).thenReturn(expectedResponse);

        ClientCredentialsTokenResponse result = keycloakClientCredentialsService.obtainToken(tenant, clientId);

        assertNotNull(result);
        assertEquals("mock_access_token", result.accessToken());
        assertEquals(3600, result.expiresIn());
    }

    @Test
    @DisplayName("Debería lanzar IllegalArgumentException si no se encuentra el secreto del cliente")
    void obtainToken_shouldThrowIllegalArgumentException_whenClientSecretIsNotFound() {
        when(keycloakProperties.getClientSecrets()).thenReturn(Collections.emptyMap());

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            keycloakClientCredentialsService.obtainToken(tenant, clientId);
        });

        assertEquals("Client secret no encontrado para: " + clientId, exception.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar IllegalStateException si la respuesta de Keycloak está vacía")
    void obtainToken_shouldThrowIllegalStateException_whenKeycloakResponseIsEmpty() {
        when(keycloakOidcClient.postRequest(
                anyString(),
                anyString(),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(ClientCredentialsTokenResponse.class)
        )).thenReturn(null); // simulamos respuesta vacía

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            keycloakClientCredentialsService.obtainToken(tenant, clientId);
        });

        assertEquals("Respuesta vacía desde Keycloak.", exception.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException en caso de error general al comunicarse con Keycloak")
    void obtainToken_shouldThrowRuntimeException_onGeneralError() {
        when(keycloakOidcClient.postRequest(
                anyString(),
                anyString(),
                any(MultiValueMap.class),
                any(HttpHeaders.class),
                eq(ClientCredentialsTokenResponse.class)
        )).thenThrow(new RuntimeException("Fallo de red"));

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            keycloakClientCredentialsService.obtainToken(tenant, clientId);
        });

        assertEquals("Error al obtener token de Keycloak.", exception.getMessage());
        assertNotNull(exception.getCause());
        assertEquals("Fallo de red", exception.getCause().getMessage());
    }
}
