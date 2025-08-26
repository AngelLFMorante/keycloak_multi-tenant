package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.exception.KeycloakCommunicationException;
import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class KeycloakIntrospectionService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakIntrospectionService.class);

    private final KeycloakProperties keycloakProperties;
    private final KeycloakConfigService utilsConfigService;
    private final RestTemplate restTemplate;

    public KeycloakIntrospectionService(KeycloakProperties keycloakProperties,
                                        KeycloakConfigService utilsConfigService,
                                        RestTemplate restTemplate) {
        this.keycloakProperties = keycloakProperties;
        this.utilsConfigService = utilsConfigService;
        this.restTemplate = restTemplate;
    }

    /**
     * Realiza la introspección del token contra Keycloak.
     *
     * @param realm    Nombre público del realm (ej. "plexus").
     * @param token    Token a validar.
     * @param clientId ID del cliente que realiza la validación.
     * @return Mapa con la respuesta del endpoint de introspección.
     * @throws KeycloakCommunicationException Si ocurre un error de comunicación con Keycloak.
     * @throws IllegalArgumentException       Si el client secret no se encuentra.
     */
    public Map<String, Object> introspectToken(String realm, RefreshTokenRequest token, String clientId) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);

        String clientSecret = keycloakProperties.getClientSecrets().get(clientId);
        if (clientSecret == null) {
            log.error("Client secret no encontrado para el cliente: {}", clientId);
            throw new IllegalArgumentException("Client secret no encontrado para: " + clientId);
        }

        String introspectUrl = String.format("%s/realms/%s/protocol/openid-connect/token/introspect",
                keycloakProperties.getAuthServerUrl(), keycloakRealm);

        log.debug("Llamando a Keycloak Introspection en {}", introspectUrl);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientId, clientSecret);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token.refreshToken());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(introspectUrl, HttpMethod.POST, request, Map.class);
            log.info("Introspection exitosa para el token. Estado activo: {}", response.getBody().getOrDefault("active", false));
            return response.getBody();
        } catch (HttpClientErrorException ex) {
            log.error("Error del cliente al llamar a Keycloak Introspection: Status={}, Body={}", ex.getStatusCode(), ex.getResponseBodyAsString(), ex);
            throw new KeycloakCommunicationException("Error del cliente al comunicarse con Keycloak: " + ex.getMessage(), ex);
        } catch (HttpServerErrorException ex) {
            log.error("Error del servidor de Keycloak: Status={}, Body={}", ex.getStatusCode(), ex.getResponseBodyAsString(), ex);
            throw new KeycloakCommunicationException("Error del servidor de Keycloak: " + ex.getMessage(), ex);
        } catch (Exception ex) {
            log.error("Error inesperado en la introspección del token: {}", ex.getMessage(), ex);
            throw new KeycloakCommunicationException("Error inesperado en la comunicación con Keycloak", ex);
        }
    }
}