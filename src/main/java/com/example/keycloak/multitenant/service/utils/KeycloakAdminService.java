package com.example.keycloak.multitenant.service.utils;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.springframework.stereotype.Service;

@Service
public class KeycloakAdminService {

    private final Keycloak keycloak;

    public KeycloakAdminService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    public RealmResource getRealmResource(String realm) {
        return keycloak.realm(realm);
    }
}