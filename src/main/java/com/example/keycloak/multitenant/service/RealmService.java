package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.RealmCreationRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakRealmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Servicio para la gestión de realms, actuando como una capa de servicio
 * que delega las operaciones administrativas a la API de Keycloak.
 * <p>
 * Esta clase encapsula la lógica de negocio para la creación de realms y
 * proporciona un punto de entrada claro para las interacciones del controlador.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class RealmService {

    private static final Logger log = LoggerFactory.getLogger(RealmService.class);
    private final KeycloakRealmService keycloakRealmService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakRealmService El servicio de cliente de administración de Keycloak.
     */
    @Autowired
    public RealmService(KeycloakRealmService keycloakRealmService) {
        this.keycloakRealmService = keycloakRealmService;
        log.info("Servicio RealmService inicializado.");
    }

    /**
     * Crea un nuevo realm en Keycloak.
     * <p>
     * Este método recibe una solicitud de creación, extrae el nombre del realm
     * y delega la operación al servicio de Keycloak. La gestión de errores
     * y la validación de duplicados se manejan en capas inferiores.
     *
     * @param request El objeto de solicitud que contiene el nombre del realm a crear.
     */
    public void createRealm(RealmCreationRequest request) {
        String realmName = request.realmName();
        log.info("Recibida solicitud de servicio para crear el realm: '{}'.", realmName);
        keycloakRealmService.createRealm(realmName);
        log.info("Realm '{}' creado con éxito.", realmName);
    }
}
