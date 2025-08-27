package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.ClientCredentialsTokenResponse;
import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.model.TokenValidationResponse;
import com.example.keycloak.multitenant.service.keycloak.KeycloakClientCredentialsService;
import com.example.keycloak.multitenant.service.keycloak.KeycloakIntrospectionService;
import com.example.keycloak.multitenant.service.utils.DataConversionUtilsService;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio principal de autenticación que coordina las operaciones con Keycloak.
 * <p>
 * Actúa como una capa de servicio que orquesta la lógica de negocio para la validación
 * de tokens y la obtención de tokens de credenciales de cliente, delegando las tareas
 * específicas a servicios más especializados.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final KeycloakIntrospectionService introspectionService;
    private final DataConversionUtilsService conversionUtilsService;
    private final KeycloakClientCredentialsService keycloakClientCredentialsService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param introspectionService             Servicio para la introspección de tokens de Keycloak.
     * @param conversionUtilsService           Servicio de utilidades para la conversión segura de datos.
     * @param keycloakClientCredentialsService Servicio para obtener tokens con credenciales de cliente.
     */
    public AuthService(KeycloakIntrospectionService introspectionService, DataConversionUtilsService conversionUtilsService, KeycloakClientCredentialsService keycloakClientCredentialsService) {
        this.introspectionService = introspectionService;
        this.conversionUtilsService = conversionUtilsService;
        this.keycloakClientCredentialsService = keycloakClientCredentialsService;
    }

    /**
     * Valida un token (access o refresh) usando el servicio de introspección de Keycloak.
     * <p>
     * Este método recibe un token y lo envía al servicio de introspección para verificar su validez.
     * Luego, mapea el resultado de la introspección (que es un {@code Map<String, Object>}) a un
     * objeto de respuesta de tipo seguro, {@link TokenValidationResponse}, utilizando el
     * servicio de conversión de utilidades para evitar errores de tipo.
     *
     * @param token    El {@link RefreshTokenRequest} que contiene el token a validar.
     * @param realm    El nombre del realm (tenant) de Keycloak.
     * @param clientId El ID del cliente de Keycloak que realiza la solicitud.
     * @return Un objeto {@link TokenValidationResponse} con los resultados de la validación.
     */
    public TokenValidationResponse validateToken(RefreshTokenRequest token, String realm, String clientId) {
        log.info("Iniciando la validación del token para el realm '{}' y cliente '{}'", realm, clientId);

        Map<String, Object> introspectionResult = introspectionService.introspectToken(realm, token, clientId);
        log.debug("Resultado de introspección recibido: {}", introspectionResult);

        TokenValidationResponse response = new TokenValidationResponse(
                (boolean) introspectionResult.getOrDefault("active", false),
                conversionUtilsService.getSafeString(introspectionResult, "token_type"),
                conversionUtilsService.getSafeString(introspectionResult, "scope"),
                conversionUtilsService.getSafeString(introspectionResult, "sub"),
                conversionUtilsService.getSafeString(introspectionResult, "session_state"),
                conversionUtilsService.getSafeList(introspectionResult, "aud"),
                conversionUtilsService.getSafeString(introspectionResult, "iss"),
                ((Number) introspectionResult.getOrDefault("exp", 0L)).longValue(),
                conversionUtilsService.getSafeString(introspectionResult, "azp"),
                conversionUtilsService.getSafeString(introspectionResult, "error_description")
        );

        log.info("Validación del token completada. Estado activo: {}", response.active());
        return response;
    }

    /**
     * Obtiene un token de acceso utilizando el flujo de Client Credentials.
     * <p>
     * Este método delega la tarea de obtener el token al {@link KeycloakClientCredentialsService}.
     * Es ideal para la comunicación de servicio a servicio, donde se utiliza el ID y el secreto
     * del cliente para autenticarse y obtener un token de acceso.
     *
     * @param tenant   El nombre del tenant (realm) de Keycloak.
     * @param clientId El ID del cliente de Keycloak.
     * @return Un objeto {@link ClientCredentialsTokenResponse} que contiene el token de acceso
     * y sus propiedades.
     */
    public ClientCredentialsTokenResponse getClientCredentialsToken(String tenant, String clientId) {
        log.info("Solicitando un token de credenciales de cliente para el tenant '{}' y cliente '{}'", tenant, clientId);
        ClientCredentialsTokenResponse tokenResponse = keycloakClientCredentialsService.obtainToken(tenant, clientId);
        log.info("Token de credenciales de cliente obtenido exitosamente.");
        return tokenResponse;
    }
}
