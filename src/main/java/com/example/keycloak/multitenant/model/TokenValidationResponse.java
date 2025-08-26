package com.example.keycloak.multitenant.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(description = "Respuesta de la validación de token de Keycloak.")
public record TokenValidationResponse(
        @Schema(description = "Indica si el token está activo y es válido.", example = "true")
        boolean active,

        @Schema(description = "Tipo de token.", example = "Bearer")
        @JsonProperty("token_type")
        String tokenType,

        @Schema(description = "Ámbitos (scopes) asociados al token.", example = "openid profile email")
        String scope,

        @Schema(description = "Sujeto (subject) del token.", example = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d")
        String sub,

        @Schema(description = "ID de la sesión de Keycloak.", example = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d-session")
        @JsonProperty("session_state")
        String sessionState,

        @Schema(description = "ID del cliente (client ID).", example = "mi-app-plexus")
        List<String> aud,

        @Schema(description = "ID del emisor (issuer).", example = "https://keycloak.example.com/realms/tenant1")
        String iss,

        @Schema(description = "Fecha de expiración del token.", example = "1730000000")
        long exp,

        @Schema(description = "ID del cliente que emitió el token.", example = "mi-app-plexus")
        String azp,

        @Schema(description = "Mensaje de error, si el token no es válido.", example = "Token inválido")
        String error
) {
}
