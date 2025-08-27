package com.example.keycloak.multitenant.model;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Record que representa la solicitud para renovar un token de acceso,
 * encapsulando el refresh token necesario.
 * <p>
 * Utiliza anotaciones de Jackson para manejar la serializacion y deserializacion
 * de JSON, permitiendo flexibilidad en los nombres de los campos de entrada.
 *
 * @param refreshToken El token de renovacion (refresh token) que se envia a Keycloak
 *                     para obtener un nuevo par de tokens de acceso y renovacion.
 * @author Angel Fm
 * @version 1.0
 */
public record RefreshTokenRequest(
        @JsonProperty("refresh_token")
        @JsonAlias({"token"})
        @Schema(description = "El refresh token para obtener un nuevo token de acceso.", example = "eyJhbGciOiJIUzUxMi...")
        String refreshToken) {
}