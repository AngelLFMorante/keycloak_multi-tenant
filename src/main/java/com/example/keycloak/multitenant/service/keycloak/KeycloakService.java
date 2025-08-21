package com.example.keycloak.multitenant.service.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para interactuar con la API de administración de Keycloak.
 * Proporciona métodos para realizar operaciones administrativas, como la creación de usuarios,
 * en un realm específico de Keycloak.
 */
@Service
public class KeycloakService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakService.class);

    /**
     * Cliente de administración de Keycloak, inyectado automáticamente.
     * Este cliente se utiliza para realizar llamadas a la API REST de administración de Keycloak.
     */
    private final Keycloak keycloak;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloak Instancia del cliente de administración de Keycloak.
     */
    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
        log.info("KeycloakService inicializado.");
    }


}
