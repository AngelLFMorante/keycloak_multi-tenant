package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class KeycloakOidcClient {

    private static final Logger log = LoggerFactory.getLogger(KeycloakOidcClient.class);
    private final RestTemplate restTemplate;
    private final KeycloakProperties keycloakProperties;

    public KeycloakOidcClient(RestTemplate restTemplate, KeycloakProperties keycloakProperties) {
        this.restTemplate = restTemplate;
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Lógica compartida para construir la URL base de un endpoint OIDC.
     */
    private String buildOidcUrl(String realm, String path) {
        return String.format("%s/realms/%s/protocol/openid-connect/%s",
                keycloakProperties.getAuthServerUrl(), realm, path);
    }

    /**
     * Método genérico para enviar una solicitud POST a un endpoint OIDC.
     */
    public <T> T postRequest(String realm, String endpointPath, MultiValueMap<String, String> body, HttpHeaders headers, Class<T> responseType) {
        String url = buildOidcUrl(realm, endpointPath);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<T> response = restTemplate.exchange(url, HttpMethod.POST, request, responseType);
            if (response.getBody() == null) {
                log.error("Respuesta vacía desde Keycloak para la URL {}", url);
                throw new IllegalStateException("Respuesta vacía desde Keycloak.");
            }
            return response.getBody();
        } catch (HttpClientErrorException ex) {
            log.error("Error del cliente al llamar a Keycloak: Status={}, Body={}", ex.getStatusCode(), ex.getResponseBodyAsString(), ex);
            throw new ResponseStatusException(ex.getStatusCode(), "Error en la comunicacion con Keycloak.", ex);
        }
    }

    /**
     * Lógica compartida para configurar la autenticación básica.
     */
    public HttpHeaders createBasicAuthHeaders(String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);
        return headers;
    }
}