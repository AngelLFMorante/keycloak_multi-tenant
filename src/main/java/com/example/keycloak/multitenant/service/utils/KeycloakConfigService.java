package com.example.keycloak.multitenant.service.utils;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class KeycloakConfigService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakConfigService.class);

    private final KeycloakProperties keycloakProperties;

    public KeycloakConfigService(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    public String resolveRealm(String realm) {
        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo no encontrado para realm '{}'", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Realm " + realm + " no reconocido");
        }
        log.debug("Realm '{}' mapeado a '{}'", realm, keycloakRealm);
        return keycloakRealm;
    }
}
