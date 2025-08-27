package com.example.keycloak.multitenant.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * Record que representa la respuesta de validacion de un token desde Keycloak.
 * <p>
 * Esta respuesta se obtiene al llamar al endpoint de introspeccion de Keycloak
 * para verificar la validez y el estado de un token de acceso. Contiene informacion
 * sobre el estado del token y sus propiedades.
 *
 * @param active       Indica si el token esta activo y es valido.
 * @param tokenType    El tipo de token, usualmente "Bearer".
 * @param scope        Una lista de los ambitos (scopes) asociados al token.
 * @param sub          El sujeto (subject) del token, generalmente el ID de usuario.
 * @param sessionState El ID de la sesion de Keycloak asociada al token.
 * @param aud          El ID del cliente (audience) al que se destina el token.
 * @param iss          El identificador del emisor del token.
 * @param exp          La fecha de expiracion del token en formato de tiempo Unix.
 * @param azp          El ID del cliente autorizado (authorized party) que emitio el token.
 * @param error        Mensaje de error si el token no es valido (presente solo cuando {@code active} es false).
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "Respuesta de la validacion de token de Keycloak.")
public record TokenValidationResponse(
        @Schema(description = "Indica si el token esta activo y es valido.", example = "true")
        boolean active,

        @Schema(description = "Tipo de token.", example = "Bearer")
        @JsonProperty("token_type")
        String tokenType,

        @Schema(description = "Ambitos (scopes) asociados al token.", example = "openid profile email")
        String scope,

        @Schema(description = "Sujeto (subject) del token.", example = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d")
        String sub,

        @Schema(description = "ID de la sesion de Keycloak.", example = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d-session")
        @JsonProperty("session_state")
        String sessionState,

        @Schema(description = "ID del cliente (client ID).", example = "mi-app-plexus")
        List<String> aud,

        @Schema(description = "ID del emisor (issuer).", example = "https://keycloak.example.com/realms/tenant1")
        String iss,

        @Schema(description = "Fecha de expiracion del token.", example = "1730000000")
        long exp,

        @Schema(description = "ID del cliente que emitio el token.", example = "mi-app-plexus")
        String azp,

        @Schema(description = "Mensaje de error, si el token no es valido.", example = "Token invalido")
        String error
) {
}