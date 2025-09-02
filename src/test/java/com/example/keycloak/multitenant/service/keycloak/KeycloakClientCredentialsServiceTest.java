package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.token.ClientCredentialsTokenResponse;
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
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
    private RestTemplate restTemplate;

    @Mock
    private KeycloakConfigService utilsConfigService;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private KeycloakClientCredentialsService keycloakClientCredentialsService;

    private String tenant;
    private String clientId;
    private String realm;
    private String clientSecret;
    private String tokenUrl;

    @BeforeEach
    void setUp() {
        tenant = "testTenant";
        clientId = "testClient";
        realm = "test-realm";
        clientSecret = "test-secret";
        tokenUrl = "http://localhost:8080/realms/test-realm/protocol/openid-connect/token";

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
        ResponseEntity<ClientCredentialsTokenResponse> responseEntity = new ResponseEntity<>(expectedResponse, HttpStatus.OK);

        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://localhost:8080");
        when(restTemplate.exchange(
                eq(tokenUrl),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(ClientCredentialsTokenResponse.class)
        )).thenReturn(responseEntity);

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
        when(keycloakProperties.getAuthServerUrl()).thenReturn("http://localhost:8080");
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(ClientCredentialsTokenResponse.class)
        )).thenReturn(new ResponseEntity<>(null, HttpStatus.OK));

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            keycloakClientCredentialsService.obtainToken(tenant, clientId);
        });

        assertEquals("Respuesta vacía desde Keycloak.", exception.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException en caso de error HTTP de Keycloak")
    void obtainToken_shouldThrowRuntimeException_onKeycloakHttpError() {
        when(restTemplate.exchange(
                eq(tokenUrl),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(ClientCredentialsTokenResponse.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Invalid client credentials"));

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            keycloakClientCredentialsService.obtainToken(tenant, clientId);
        });

        assertEquals("Error al obtener token de Keycloak.", exception.getMessage());
    }
}
