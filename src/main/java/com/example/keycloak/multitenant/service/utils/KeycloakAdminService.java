package com.example.keycloak.multitenant.service.utils;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para obtener recursos administrativos de un realm de Keycloak.
 * <p>
 * Esta clase actúa como un proveedor para el cliente administrativo de Keycloak,
 * facilitando la obtención de una instancia de {@link RealmResource} para
 * realizar operaciones de administración a nivel de realm.
 *
 * @author Angel Fm
 * @version 1.0
 * @see Keycloak
 * @see RealmResource
 */
@Service
public class KeycloakAdminService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAdminService.class);
    private final Keycloak keycloak;

    /**
     * Constructor para la inyección de dependencias del cliente de administración de Keycloak.
     *
     * @param keycloak La instancia del cliente de administración de Keycloak.
     */
    public KeycloakAdminService(Keycloak keycloak) {
        this.keycloak = keycloak;
        log.info("Servicio de administración de Keycloak inicializado.");
    }

    public RealmResource getRealmResource(String realm) {
        log.debug("Obteniendo recurso de realm para: '{}'", realm);
        return keycloak.realm(realm);
    }
}