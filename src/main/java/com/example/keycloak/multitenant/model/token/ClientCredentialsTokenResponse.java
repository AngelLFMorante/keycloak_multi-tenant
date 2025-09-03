package com.example.keycloak.multitenant.model.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Record que representa la respuesta de un token obtenido a traves del
 * flujo de autenticacion 'Client Credentials' de Keycloak.
 * <p>
 * Este flujo se utiliza para que las aplicaciones (no usuarios finales)
 * se autentiquen y obtengan un token para acceder a la API de administracion.
 *
 * @param accessToken      El token de acceso JWT.
 * @param expiresIn        Tiempo de vida del token de acceso en segundos.
 * @param refreshExpiresIn Tiempo de vida del token de renovacion en segundos (normalmente 0 en este flujo).
 * @param tokenType        Tipo de token (ej. "Bearer").
 * @param scope            El ambito del token, que define los permisos de acceso.
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "Respuesta del token obtenido a traves de 'Client Credentials'.")
public record ClientCredentialsTokenResponse(
        @Schema(description = "El token de acceso JWT.", example = "eyJ...")
        @JsonProperty("access_token")
        String accessToken,

        @Schema(description = "Tiempo de vida del access token en segundos.", example = "3600")
        @JsonProperty("expires_in")
        long expiresIn,

        @Schema(description = "Tiempo de vida del refresh token en segundos.", example = "0")
        @JsonProperty("refresh_expires_in")
        long refreshExpiresIn,

        @Schema(description = "Tipo de token.", example = "Bearer")
        @JsonProperty("token_type")
        String tokenType,

        @Schema(description = "El ambito del token.", example = "openid")
        String scope
) {
}