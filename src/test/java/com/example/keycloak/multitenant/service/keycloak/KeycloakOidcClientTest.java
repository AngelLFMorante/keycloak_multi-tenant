package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para la clase KeycloakOidcClient, validando
 * el manejo de solicitudes HTTP y la creación de cabeceras de autenticación.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for KeycloakOidcClient")
class KeycloakOidcClientTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private KeycloakOidcClient keycloakOidcClient;

    private final String authServerUrl = "http://keycloak.local";
    private final String realm = "testRealm";
    private final String clientId = "test-client";
    private final String clientSecret = "test-secret";

    @Test
    @DisplayName("Debería enviar una solicitud POST y retornar el cuerpo de la respuesta")
    void postRequest_Success() {
        String endpointPath = "token";
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        Map<String, Object> mockResponseBody = Map.of("access_token", "mock-token");
        when(keycloakProperties.getAuthServerUrl()).thenReturn(authServerUrl);
        when(restTemplate.exchange(
                anyString(),
                any(),
                any(),
                eq(Map.class)
        )).thenReturn(new ResponseEntity<>(mockResponseBody, HttpStatus.OK));

        Map<String, Object> result = keycloakOidcClient.postRequest(
                realm,
                endpointPath,
                body,
                headers,
                Map.class
        );

        assertNotNull(result);
        assertEquals("mock-token", result.get("access_token"));
    }

    @Test
    @DisplayName("Debería lanzar ResponseStatusException si la solicitud falla con un error de cliente")
    void postRequest_HttpClientErrorException() {
        String endpointPath = "token";
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        when(keycloakProperties.getAuthServerUrl()).thenReturn(authServerUrl);
        when(restTemplate.exchange(
                anyString(),
                any(),
                any(),
                eq(Map.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Invalid request"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                keycloakOidcClient.postRequest(realm, endpointPath, body, headers, Map.class)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getMessage().contains("Error en la comunicacion con Keycloak."));
    }

    @Test
    @DisplayName("Debería lanzar IllegalStateException si el cuerpo de la respuesta es nulo")
    void postRequest_EmptyBody() {
        String endpointPath = "token";
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        when(keycloakProperties.getAuthServerUrl()).thenReturn(authServerUrl);
        when(restTemplate.exchange(
                anyString(),
                any(),
                any(),
                eq(Map.class)
        )).thenReturn(new ResponseEntity<>(null, HttpStatus.OK));

        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
                keycloakOidcClient.postRequest(realm, endpointPath, body, headers, Map.class)
        );

        assertEquals("Respuesta vacía desde Keycloak.", exception.getMessage());
    }

    @Test
    @DisplayName("Debería crear correctamente las cabeceras de autenticación básica")
    void createBasicAuthHeaders_Success() {
        String expectedAuth = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = keycloakOidcClient.createBasicAuthHeaders(clientId, clientSecret);

        assertNotNull(headers);
        assertTrue(headers.containsKey("Authorization"));
        assertEquals(expectedAuth, headers.getFirst("Authorization"));
    }
}
