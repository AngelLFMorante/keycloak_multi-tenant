package com.example.keycloak.multitenant.model;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Record que representa la solicitud para renovar un token de acceso,
 * encapsulando el refresh token necesario.
 */
public record RefreshTokenRequest(
        @JsonProperty("refresh_token")
        @JsonAlias({"token"})
        @Schema(description = "El refresh token para obtener un nuevo token de acceso.", example = "eyJhbGciOiJIUzUxMi...")
        String refreshToken) {
}
