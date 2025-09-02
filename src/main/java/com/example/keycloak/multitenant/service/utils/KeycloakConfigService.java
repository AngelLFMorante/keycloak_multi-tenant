package com.example.keycloak.multitenant.service.utils;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio de configuración para resolver y mapear nombres de tenants a realms de Keycloak.
 * <p>
 * Se encarga de traducir los nombres de los tenants públicos, utilizados en las rutas de la API,
 * a los nombres de los realms internos de Keycloak según la configuración de la aplicación.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakConfigService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakConfigService.class);

    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakProperties Las propiedades de configuración de Keycloak.
     */
    public KeycloakConfigService(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Valida y resuelve el realm interno de Keycloak a partir del nombre público del tenant.
     * <p>
     * Este método busca el nombre del realm en el mapa de configuración y, si no lo encuentra,
     * lanza una excepción para indicar que el tenant no está reconocido.
     *
     * @param realm El nombre del tenant (ej. 'plexus').
     * @return El nombre del realm interno de Keycloak (ej. 'plexus-realm').
     * @throws ResponseStatusException Si no se encuentra un mapeo para el realm dado.
     */
    public String resolveRealm(String realm) {
        log.info("Resolviendo el realm público '{}'", realm);
        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo no encontrado para realm '{}'", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Realm " + realm + " no reconocido");
        }
        log.debug("Realm '{}' mapeado a '{}'", realm, keycloakRealm);
        return keycloakRealm;
    }
}
