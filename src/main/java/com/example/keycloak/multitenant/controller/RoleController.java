package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.KeycloakService;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Controlador REST para gestionar las operaciones de roles en Keycloak.
 * Proporcioina endpoints para crear, eliminar, obtener y actualizar roles.
 */
@RestController
@RequestMapping("/api/v1")
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

    @GetMapping("/{realm}/roles")
    public ResponseEntity<List<RoleRepresentation>> getRoles(@PathVariable String realm) {
        log.info("Solicitud para obtener roles del realm '{}'.", realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el realmPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Realm " + realm + " no reconocido.");
        }
        log.debug("RealmPath '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        try {
            List<RoleRepresentation> roles = keycloakService.getRoles(keycloakRealm);
            return ResponseEntity.ok(roles);
        } catch (Exception e) {
            log.error("Error al obtener roles del realm '{}': {}", keycloakRealm, e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "error al obtener roles: " + e.getMessage(), e);
        }

    }

    /**
     * Maneja las solicitudes POST para crear un nuevo rol en un realm específico.
     *
     * @param realm   El nombre del tenant (path) para el cual se creará el rol.
     * @param request El objeto {@link CreateRoleRequest} que contiene los datos del nuevo rol.
     * @return Un {@link ResponseEntity} con el estado de éxito o error de la operación.
     */
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

    /**
     * Maneja las solicitudes DELETE para eliminar un rol por su nombre en un realm específico.
     *
     * @param realm    El nombre del tenant (path) del cual se eliminará el rol.
     * @param roleName El nombre del rol a eliminar.
     * @return Un {@link ResponseEntity} con el estado de éxito o error de la operación.
     */
    @DeleteMapping("/{realm}/roles/{roleName}")
    public ResponseEntity<Map<String, Object>> deleteRole(@PathVariable String realm, @PathVariable String roleName) {
        log.info("Solicitud para eliminar rol '{}' del tenant  '{}'.", roleName, realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el realm: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Realm " + realm + " no reconocido.");
        }
        log.debug("Realm '{}' mapeando al realm de Keycloak: '{}'", realm, keycloakRealm);

        try {
            keycloakService.deleteRole(keycloakRealm, roleName);
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Rol '" + roleName + "' eliminado exitosamente.");
            response.put("realm", realm);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Error al eliminar el rol '{}' del realm '{}': {}", roleName, keycloakRealm, e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al eliminar el rol: " + e.getMessage(), e);
        }
    }
}
