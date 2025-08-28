package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.ClientCredentialsTokenResponse;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * Servicio para obtener tokens de acceso desde Keycloak utilizando el flujo de 'Client Credentials'.
 * <p>
 * Este servicio es responsable de construir y enviar peticiones HTTP a Keycloak para
 * autenticar un cliente de servicio (machine-to-machine) y obtener un token de acceso.
 * Utiliza {@link RestTemplate} para la comunicación y delega la resolución de la configuración
 * a {@link KeycloakConfigService}.
 *
 * @author Angel Fm
 * @version 1.0
 * @see KeycloakConfigService
 * @see ClientCredentialsTokenResponse
 */
@Service
public class KeycloakClientCredentialsService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakClientCredentialsService.class);

    private final RestTemplate restTemplate;
    private final KeycloakConfigService utilsConfigService;
    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param restTemplate       El cliente HTTP para realizar las peticiones a Keycloak.
     * @param utilsConfigService El servicio de configuración de Keycloak para resolver realms.
     * @param keycloakProperties Las propiedades de configuración de Keycloak de la aplicación.
     */
    public KeycloakClientCredentialsService(RestTemplate restTemplate,
                                            KeycloakConfigService utilsConfigService,
                                            KeycloakProperties keycloakProperties) {
        this.restTemplate = restTemplate;
        this.utilsConfigService = utilsConfigService;
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Obtiene un token de acceso desde Keycloak utilizando el flujo de 'client_credentials'.
     * <p>
     * Este método construye la petición para autenticarse como un cliente de servicio,
     * enviando el `client_id` y el `client_secret` al endpoint de tokens de Keycloak.
     * Si no se encuentra el secreto del cliente, se lanza una excepción.
     *
     * @param tenant   El nombre público del tenant para el cual se solicita el token.
     * @param clientId El ID del cliente que solicita el token.
     * @return Un objeto {@link ClientCredentialsTokenResponse} que contiene los datos del token.
     * @throws IllegalArgumentException Si el secreto del cliente no se encuentra en la configuración.
     * @throws IllegalStateException    Si la respuesta de Keycloak está vacía.
     * @throws RuntimeException         En caso de un error general de comunicación con Keycloak.
     */
    public ClientCredentialsTokenResponse obtainToken(String tenant, String clientId) {
        log.info("Iniciando la solicitud para obtener token 'Client Credentials' para el cliente '{}' en el tenant '{}'", clientId, tenant);

        String realm = utilsConfigService.resolveRealm(tenant);
        String clientSecret = keycloakProperties.getClientSecrets().get(clientId);

        if (clientSecret == null) {
            log.error("No se encontró el secret para el cliente: {}", clientId);
            throw new IllegalArgumentException("Client secret no encontrado para: " + clientId);
        }

        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token",
                keycloakProperties.getAuthServerUrl(), realm);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        log.debug("Solicitando token a Keycloak en {} con clientId={}", tokenUrl, clientId);

        try {
            ResponseEntity<ClientCredentialsTokenResponse> response =
                    restTemplate.exchange(tokenUrl, HttpMethod.POST, request, ClientCredentialsTokenResponse.class);
            ClientCredentialsTokenResponse responseBody = response.getBody();

            if (responseBody == null) {
                log.error("Respuesta vacía desde Keycloak para clientId={}", clientId);
                throw new IllegalStateException("Respuesta vacía desde Keycloak.");
            }

            log.info("Token obtenido exitosamente para clientId={}", clientId);
            return responseBody;
        } catch (IllegalStateException | IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Error al obtener token de Keycloak: {}", ex.getMessage(), ex);
            throw new RuntimeException("Error al obtener token de Keycloak.", ex);
        }
    }
}