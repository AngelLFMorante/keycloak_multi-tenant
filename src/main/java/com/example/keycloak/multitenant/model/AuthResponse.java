package com.example.keycloak.multitenant.model;

import java.util.List;
import lombok.Data;

/**
 * DTO que encapsula la respuesta de autenticación o renovación de token de Keycloak.
 * Contiene los tokens, información del usuario y roles extraídos.
 */
@Data
public class AuthResponse {
    private String accessToken;
    private String idToken;
    private String refreshToken;
    private long expiresIn;
    private long refreshExpiresIn;
    private String username;
    private String email;
    private String fullName;
    private List<String> roles;
    private String realm;
    private String client;
    private String preferredUsername;

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

    // Constructor para refresh token (sin username, email, fullName, roles)
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

