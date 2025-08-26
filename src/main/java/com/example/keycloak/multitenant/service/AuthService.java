package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.model.TokenValidationResponse;
import com.example.keycloak.multitenant.service.keycloak.KeycloakIntrospectionService;
import com.example.keycloak.multitenant.service.utils.DataConversionUtilsService;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final KeycloakIntrospectionService introspectionService;
    private final DataConversionUtilsService conversionUtilsService;

    public AuthService(KeycloakIntrospectionService introspectionService, DataConversionUtilsService conversionUtilsService) {
        this.introspectionService = introspectionService;
        this.conversionUtilsService = conversionUtilsService;
    }

    /**
     * Valida el token usando el servicio de introspección y lo mapea a un objeto de respuesta.
     *
     * @param token    El token a validar.
     * @param realm    Nombre del realm.
     * @param clientId ID del cliente que solicita la validación.
     * @return Objeto de respuesta con el resultado de la introspección.
     */
    public TokenValidationResponse validateToken(RefreshTokenRequest token, String realm, String clientId) {
        Map<String, Object> introspectionResult = introspectionService.introspectToken(realm, token, clientId);
        return new TokenValidationResponse(
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
    }
}
