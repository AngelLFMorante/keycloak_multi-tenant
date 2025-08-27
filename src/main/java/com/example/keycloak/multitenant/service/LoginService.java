package com.example.keycloak.multitenant.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.utils.DataConversionUtilsService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio para manejar la autenticacion y renovacion de tokens con Keycloak
 * utilizando el flujo de Password Grant Type y Refresh Token.
 * Esta clase encapsula la logica de comunicacion directa con los endpoints de Keycloak.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate;
    private final KeycloakProperties keycloakProperties;
    private final DataConversionUtilsService dataConversionUtilsService;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param restTemplate       Instancia de RestTemplate para realizar llamadas HTTP.
     * @param keycloakProperties Propiedades de configuracion de Keycloak.
     */
    public LoginService(RestTemplate restTemplate, KeycloakProperties keycloakProperties, DataConversionUtilsService dataConversionUtilsService) {
        this.restTemplate = restTemplate;
        this.keycloakProperties = keycloakProperties;
        this.dataConversionUtilsService = dataConversionUtilsService;
        log.info("LoginService inicializado.");
    }

    /**
     * Autentica a un usuario contra Keycloak utilizando el flujo de Password Grant.
     * Extrae y devuelve los tokens y la informacion del usuario.
     *
     * @param realm    El nombre del realm (tenant) de la aplicacion.
     * @param client   El ID del cliente de Keycloak.
     * @param username El nombre de usuario.
     * @param password La contrasena del usuario.
     * @return Un objeto AuthResponse que contiene los tokens y la informacion del usuario.
     * @throws ResponseStatusException  Si el tenant o cliente no son reconocidos, o si hay un error de comunicacion con Keycloak.
     * @throws IllegalArgumentException Si el secreto del cliente no esta configurado.
     */
    public LoginResponse authenticate(String realm, String client, String username, String password) {
        log.info("Intentando autenticar usuario '{}' en tenant '{}' con cliente keycloak '{}'", username, realm, client);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        String clientSecret = keycloakProperties.getClientSecrets().get(client);
        if (clientSecret == null) {
            log.warn("Client Secret no encontrado para el Client ID: {}", client);
            throw new IllegalArgumentException("Client ID configurado pero secreto no encontrado para: " + client + "." +
                    "Asegurate de que el client ID esté configurado en 'keycloak.client-secrets' en properties.");
        }
        log.debug("Client Secret encontrado para Client ID: {}", client);

        String tokenUrl = keycloakProperties.getAuthServerUrl() + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";
        log.debug("URL de token de Keycloak: {}", tokenUrl);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", client);
        params.add("username", username);
        params.add("password", password);
        params.add("scope", "openid profile email");
        log.debug("Parametros de solicitud de token: {}", params);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String clientAuth = client + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);
        log.debug("Cabeceras de autenticación preparados.");

        ResponseEntity<String> tokenResponseEntity;
        try {
            tokenResponseEntity = restTemplate.postForEntity(
                    tokenUrl,
                    new HttpEntity<>(params, headers),
                    String.class
            );
        } catch (HttpClientErrorException e) {
            log.error("Error al autenticar con Keycloak: Status={}, Body={}", e.getStatusCode(), e.getResponseBodyAsString(), e);
            throw new ResponseStatusException(e.getStatusCode(), "Error al autenticar con Keycloak: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Error inesperado durante la autenticación con Keycloak: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error inesperado durante la autenticación.", e);
        }

        String tokenResponse = tokenResponseEntity.getBody();
        log.info("Respuesta exitosa de Keycloak para el usuario '{}'", username);

        try {
            JsonNode node = objectMapper.readTree(tokenResponse);

            String accessToken = node.get("access_token").asText();
            String idToken = node.has("id_token") ? node.get("id_token").asText() : null;
            String refreshToken = node.has("refresh_token") ? node.get("refresh_token").asText() : null;
            long expiresIn = node.has("expires_in") ? node.get("expires_in").asLong() : 0;
            long refreshExpiresIn = node.has("refresh_expires_in") ? node.get("refresh_expires_in").asLong() : 0;

            List<String> extractedRoles = new ArrayList<>();
            String email = null;
            String fullName = null;
            String preferredUsername = username;

            DecodedJWT decodedAccessToken = JWT.decode(accessToken);
            log.debug("Access Token decodificado para extracción de claims y roles.");

            email = decodedAccessToken.getClaim("email") != null ? decodedAccessToken.getClaim("email").asString() : null;
            fullName = decodedAccessToken.getClaim("name") != null ? decodedAccessToken.getClaim("name").asString() : null;
            preferredUsername = decodedAccessToken.getClaim("preferred_username") != null ? decodedAccessToken.getClaim("preferred_username").asString() : username;
            log.debug("Claims de usuario extraidos (desde Access Token): email={}, fullName={}, preferredUsername={}", email, fullName, preferredUsername);

            Map<String, Object> realmAccess = decodedAccessToken.getClaim("realm_access").asMap();
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> realmRoles = (List<String>) realmAccess.get("roles");
                if (realmRoles != null) {
                    realmRoles.forEach(role -> extractedRoles.add("ROLE_" + role.toUpperCase()));
                    log.debug("Roles de realm extraidos (desde Access Token): {}", realmRoles);
                }
            }

            Map<String, Object> resourceAccess = decodedAccessToken.getClaim("resource_access").asMap();
            if (resourceAccess != null && resourceAccess.containsKey(client)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(client);
                if (clientAccess != null && clientAccess.containsKey("roles")) {
                    @SuppressWarnings("unchecked")
                    List<String> clientRoles = (List<String>) clientAccess.get("roles");
                    if (clientRoles != null) {
                        clientRoles.forEach(role -> extractedRoles.add("ROLE_" + role.toUpperCase()));
                        log.debug("Roles de cliente '{}' extraidos (desde Access Token): {}", client, clientRoles);
                    }
                }
            }

            return new LoginResponse(accessToken, idToken, refreshToken, expiresIn, refreshExpiresIn,
                    username, email, fullName, extractedRoles, realm, client, preferredUsername);

        } catch (Exception e) {
            log.error("Error al procesar la respuesta de tokens de Keycloak: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al procesar la respuesta de Keycloak.", e);
        }
    }

    /**
     * Renueva un token de acceso utilizando un refresh token con Keycloak.
     *
     * @param oldRefreshToken El refresh token actual.
     * @param realm           El nombre del realm (tenant) de la aplicación.
     * @param client          El ID del cliente de Keycloak.
     * @return Un objeto AuthResponse con los nuevos tokens y su información.
     * @throws ResponseStatusException  Si el tenant o cliente no son reconocidos, si el refresh token es inválido,
     *                                  o si hay un error de comunicación con Keycloak.
     * @throws IllegalArgumentException Si el secreto del cliente no está configurado.
     */
    public LoginResponse refreshToken(String oldRefreshToken, String realm, String client) {
        log.info("Intentando renovar token para tenant '{}' con cliente keycloak '{}'", realm, client);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }

        String clientSecret = keycloakProperties.getClientSecrets().get(client);
        if (clientSecret == null) {
            log.warn("Client Secret no encontrado para el Client ID: {}", client);
            throw new IllegalArgumentException("Client ID configurado pero secreto no encontrado para: " + client + ".");
        }

        String tokenUrl = keycloakProperties.getAuthServerUrl() + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("client_id", client);
        params.add("refresh_token", oldRefreshToken);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String clientAuth = client + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);

        ResponseEntity<String> tokenResponseEntity;
        try {
            tokenResponseEntity = restTemplate.postForEntity(
                    tokenUrl,
                    new HttpEntity<>(params, headers),
                    String.class
            );
        } catch (HttpClientErrorException e) {
            log.error("Error al renovar token con Keycloak: Status={}, Body={}", e.getStatusCode(), e.getResponseBodyAsString(), e);
            throw new ResponseStatusException(e.getStatusCode(), "Fallo al renovar token con Keycloak: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Error inesperado al renovar token: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error inesperado durante la renovación del token.", e);
        }

        String tokenResponse = tokenResponseEntity.getBody();
        log.info("Respuesta exitosa de Keycloak para la renovación de token.");

        try {
            JsonNode node = objectMapper.readTree(tokenResponse);

            String newAccessToken = node.get("access_token").asText();
            String newIdToken = node.has("id_token") ? node.get("id_token").asText() : null;
            String newRefreshToken = node.has("refresh_token") ? node.get("refresh_token").asText() : null;
            long newExpiresIn = node.has("expires_in") ? node.get("expires_in").asLong() : 0;
            long newRefreshExpiresIn = node.has("refresh_expires_in") ? node.get("refresh_expires_in").asLong() : 0;

            return new LoginResponse(newAccessToken, newIdToken, newRefreshToken, newExpiresIn, newRefreshExpiresIn,
                    realm, client);

        } catch (Exception e) {
            log.error("Error al procesar la respuesta de renovación de tokens de Keycloak: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al procesar la respuesta de renovación de Keycloak.", e);
        }
    }

    /**
     * Revoca un refresh token (logout) para cerrar sesión del usuario en Keycloak.
     *
     * @param refreshToken El refresh token a revocar.
     * @param realm        El realm desde donde se emitió el token.
     * @param client       El client ID registrado en Keycloak.
     */
    public void revokeRefreshToken(String refreshToken, String realm, String client) {
        log.info("Revocando refresh token para logout en realm '{}' y client '{}'", realm, client);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.error("Secreto de cliente no encontrado para client: {}", client);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Realm no reconocido.");
        }

        String clientSecret = keycloakProperties.getClientSecrets().get(client);
        if (clientSecret == null) {
            log.error("Secreto del cliente no encontrado para client: {}", client);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client ID no valido para logout.");
        }

        String revokeUrl = keycloakProperties.getAuthServerUrl() + "/realms/" + keycloakRealm + "/protocol/openid-connect/revoke";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String clientAuth = client + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("token", refreshToken);
        params.add("token_type_hint", "refresh_token");

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

        try {
            restTemplate.postForEntity(revokeUrl, entity, String.class);
            log.info("Refresh token revocado correctamente para el realm '{}' y client '{}'", realm, client);
        } catch (Exception e) {
            log.error("Error al revocar el token: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al revocar token en Keycloak.");
        }

    }
}

