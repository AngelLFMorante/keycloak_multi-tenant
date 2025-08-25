package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import lombok.Data;

/**
 * DTO que encapsula la respuesta de autenticación o renovación de token de Keycloak.
 * Contiene los tokens, información del usuario y roles extraídos.
 */
@Data
@Schema(description = "Respuesta de autenticacion o renovacion de token que contiene los tokens y la informacion del usuario.")
public class AuthResponse {
    @Schema(description = "El token de acceso JWT.", example = "eyJ...")
    private String accessToken;
    @Schema(description = "El token de identidad JWT.", example = "eyJ...")
    private String idToken;
    @Schema(description = "El token de renovacion para obtener un nuevo token de acceso.", example = "eyJ...")
    private String refreshToken;
    @Schema(description = "Tiempo de vida del access token en segundos.", example = "300")
    private long expiresIn;
    @Schema(description = "Tiempo de vida del refresh token en segundos.", example = "1800")
    private long refreshExpiresIn;
    @Schema(description = "El nombre de usuario.", example = "user.test")
    private String username;
    @Schema(description = "La direccion de correo electronico del usuario.", example = "user@test.com")
    private String email;
    @Schema(description = "El nombre completo del usuario.", example = "Test User")
    private String fullName;
    @Schema(description = "Una lista de los roles asignados al usuario.", example = "['ROLE_USER', 'ROLE_ADMIN']")
    private List<String> roles;
    @Schema(description = "El identificador del tenant (realm).", example = "tenant1")
    private String realm;
    @Schema(description = "El ID del cliente de Keycloak.", example = "mi-app-plexus")
    private String client;
    @Schema(description = "El nombre de usuario preferido extraido del token JWT.", example = "user.test")
    private String preferredUsername;

    /**
     * Constructor para la respuesta de login completo.
     */
    public AuthResponse(String accessToken, String idToken, String refreshToken, long expiresIn, long refreshExpiresIn,
                        String username, String email, String fullName, List<String> roles, String realm, String client, String preferredUsername) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        this.username = username;
        this.email = email;
        this.fullName = fullName;
        this.roles = roles;
        this.realm = realm;
        this.client = client;
        this.preferredUsername = preferredUsername;
    }

    /**
     * Constructor para la respuesta de renovacion de token (sin informacion de usuario detallada).
     */
    public AuthResponse(String accessToken, String idToken, String refreshToken, long expiresIn, long refreshExpiresIn,
                        String realm, String client) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        this.realm = realm;
        this.client = client;
    }
}

