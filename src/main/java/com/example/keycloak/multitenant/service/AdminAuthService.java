package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.stereotype.Service;

@Service
public class AdminAuthService {

    private final KeycloakProperties keycloakProperties;

    public AdminAuthService(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    public AccessTokenResponse loginAsAdmin() {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getAuthServerUrl())
                .realm(keycloakProperties.getAdmin().getRealm())
                .username(keycloakProperties.getAdmin().getUsername())
                .password(keycloakProperties.getAdmin().getPassword())
                .clientId(keycloakProperties.getAdmin().getClientId())
                .build();

        return keycloak.tokenManager().getAccessToken();
    }
}
