package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.KeycloakService;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Controlador REST para gestionar las operaciones de roles en Keycloak.
 * Proporcioina endpoints para crear, eliminar, obtener y actualizar roles.
 */
@RestController
public class RoleController {

    private static final Logger log = LoggerFactory.getLogger(RoleController.class);

    private final KeycloakService keycloakService;
    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor pra inyeccion de dependencias
     *
     * @param keycloakService    El servicio {@link KeycloakService} para interactuar con Keycloak.
     * @param keycloakProperties Las propiedades de configuracion de Keycloak.
     */
    public RoleController(KeycloakService keycloakService, KeycloakProperties keycloakProperties) {
        this.keycloakService = keycloakService;
        this.keycloakProperties = keycloakProperties;
    }

    @PostMapping("/{realm}/roles")
    public ResponseEntity<Map<String, Object>> createRole(@PathVariable String realm, @Valid @RequestBody CreateRoleRequest request) {
        log.info("Solicitud para crear rol '{}' en el realm '{}'.", request.getName(), realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el realmPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Realm " + realm + "no reconocido.");
        }
        log.debug("RealmPath '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        try {
            keycloakService.createRole(keycloakRealm, request);
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Rol creado exitosamente.");
            response.put("roleName", request.getName());
            response.put("realm", realm);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (RuntimeException e) {
            log.error("Error al crear el rol '{}' en el realm '{}': {}", request.getName(), keycloakRealm, e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al crear el rol: " + e.getMessage(), e);
        }
    }
}
