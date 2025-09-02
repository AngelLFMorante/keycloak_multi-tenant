package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.exception.KeycloakCommunicationException;
import com.example.keycloak.multitenant.model.token.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio para realizar la introspeccion de tokens con el servidor de Keycloak.
 * <p>
 * La introspeccion permite a la aplicacion cliente validar un token de forma
 * segura consultando al servidor de autorizacion. Esto es util para verificar
 * la validez de un refresh token antes de intentar usarlo.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakIntrospectionService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakIntrospectionService.class);

    private final KeycloakProperties keycloakProperties;
    private final KeycloakConfigService utilsConfigService;
    private final RestTemplate restTemplate;
    private final KeycloakOidcClient keycloakOidcClient;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param keycloakProperties Propiedades de configuracion de Keycloak.
     * @param utilsConfigService Servicio de utilidades para la configuracion.
     * @param restTemplate       Cliente HTTP para realizar las llamadas a la API de Keycloak.
     */
    public KeycloakIntrospectionService(KeycloakProperties keycloakProperties,
                                        KeycloakConfigService utilsConfigService,
                                        RestTemplate restTemplate, KeycloakOidcClient keycloakOidcClient) {
        this.keycloakProperties = keycloakProperties;
        this.utilsConfigService = utilsConfigService;
        this.restTemplate = restTemplate;
        this.keycloakOidcClient = keycloakOidcClient;
    }

    /**
     * Realiza la introspeccion de un token contra el endpoint de Keycloak.
     * <p>
     * Este metodo envia el token y las credenciales del cliente al servidor
     * de Keycloak para verificar su validez y estado.
     *
     * @param realm    Nombre publico del realm (ej. "tenant1").
     * @param token    El token a validar, encapsulado en un {@link RefreshTokenRequest}.
     * @param clientId ID del cliente que realiza la validacion.
     * @return Un {@link Map} con la respuesta JSON del endpoint de introspeccion.
     * Normalmente contiene el campo 'active' (boolean) y otros detalles del token.
     * @throws KeycloakCommunicationException Si ocurre un error de comunicacion con Keycloak,
     *                                        como un error HTTP de cliente o servidor.
     * @throws IllegalArgumentException       Si el secret del cliente no se encuentra en las propiedades.
     */
    public Map<String, Object> introspectToken(String realm, RefreshTokenRequest token, String clientId) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);

        String clientSecret = keycloakProperties.getClientSecrets().get(clientId);
        if (clientSecret == null) {
            log.error("Client secret no encontrado para el cliente: {}", clientId);
            throw new IllegalArgumentException("Client secret no encontrado para: " + clientId);
        }

        HttpHeaders headers = keycloakOidcClient.createBasicAuthHeaders(clientId, clientSecret);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token.refreshToken());

        try {
            Map<String, Object> responseBody = keycloakOidcClient.postRequest(
                    keycloakRealm,
                    "token/introspect",
                    body,
                    headers,
                    Map.class
            );
            log.info("Introspection exitosa para el token. Estado activo: {}", responseBody.getOrDefault("active", false));
            return responseBody;
        } catch (ResponseStatusException ex) {
            log.error("Error al llamar a Keycloak Introspection: {}", ex.getMessage(), ex);
            throw ex;
        }
    }
}