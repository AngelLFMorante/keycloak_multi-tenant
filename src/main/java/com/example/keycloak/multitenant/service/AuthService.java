package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.model.TokenValidationResponse;
import com.example.keycloak.multitenant.service.keycloak.KeycloakIntrospectionService;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUtilsService;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final KeycloakIntrospectionService introspectionService;

    public AuthService(KeycloakIntrospectionService introspectionService, KeycloakUtilsService utilsService) {
        this.introspectionService = introspectionService;
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
                (String) introspectionResult.get("token_type"),
                (String) introspectionResult.get("scope"),
                (String) introspectionResult.get("sub"),
                (String) introspectionResult.get("session_state"),
                (List<String>) introspectionResult.get("aud"),
                (String) introspectionResult.get("iss"),
                ((Number) introspectionResult.getOrDefault("exp", 0L)).longValue(),
                (String) introspectionResult.get("azp"),
                (String) introspectionResult.get("error_description")
        );
    }
}
