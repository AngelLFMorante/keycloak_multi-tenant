package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio para interactuar con la API de administración de Keycloak.
 * Proporciona métodos para realizar operaciones administrativas, como la creación de usuarios,
 * en un realm específico de Keycloak.
 */
@Service
public class KeycloakUtilsService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUtilsService.class);

    /**
     * Cliente de administración de Keycloak, inyectado automáticamente.
     * Este cliente se utiliza para realizar llamadas a la API REST de administración de Keycloak.
     */
    private final Keycloak keycloak;

    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloak Instancia del cliente de administración de Keycloak.
     */
    public KeycloakUtilsService(Keycloak keycloak, KeycloakProperties keycloakProperties) {
        this.keycloak = keycloak;
        this.keycloakProperties = keycloakProperties;
        log.info("KeycloakUtilsService inicializado.");
    }

    /**
     * Obtiene el recurso de realm de Keycloak para el realm especificado.
     *
     * @param realm El nombre del realm de Keycloak.
     * @return Una instancia de {@link RealmResource} para el realm.
     */
    public RealmResource getRealmResource(String realm) {
        return keycloak.realm(realm);
    }

    /**
     * Valida y resuelve el realm interno de Keycloak a partir del nombre público del tenant.
     *
     * @param realm Nombre del tenant.
     * @return Realm de Keycloak.
     * @throws ResponseStatusException Si no se encuentra el mapeo.
     */
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
