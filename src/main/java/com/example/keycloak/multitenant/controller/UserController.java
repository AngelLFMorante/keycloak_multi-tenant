package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.KeycloakService;
import com.example.keycloak.multitenant.service.UserService;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Controlador REST para gestionar el proceso de registro de nuevos usuarios en Keycloak.
 * Maneja la visualización del formulario de registro y el procesamiento de la solicitud de registro.
 * La creación de usuarios en Keycloak se delega a {@link KeycloakService}.
 */
@RestController
@RequestMapping("/api/v1")
public class UserController {

    private static Logger log = LoggerFactory.getLogger(UserController.class);
    /**
     * Servicio que interactúa con la API de administración de Keycloak para operaciones relacionadas con usuarios.
     */
    private final KeycloakService keycloakService;

    private final KeycloakProperties keycloakProperties;
    private final UserService userService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakService El servicio {@link KeycloakService} para interactuar con Keycloak.
     */
    public UserController(KeycloakService keycloakService, KeycloakProperties keycloakProperties, UserService userService) {
        this.keycloakService = keycloakService;
        this.keycloakProperties = keycloakProperties;
        this.userService = userService;
        log.info("UserController inicializado.");
    }

    //TODO Hay que eliminar register get para obtener el form en front y login lo gestiona todo GO

    /**
     * Maneja las solicitudes GET para informar sobre el endpoint de registro de un tenant específico.
     *
     * @param realm El nombre del realm (tenant) para el cual se va a registrar el usuario.
     * @return El nombre de la vista ("register") que contiene el formulario de registro.
     */
    @GetMapping("/{realm}/register")
    public ResponseEntity<Map<String, Object>> showRegisterForm(@PathVariable String realm) {
        log.info("Solicitud GET para información de registro del tenant: {}", realm);
        Map<String, Object> response = new HashMap<>();
        response.put("realm", realm);
        response.put("registerRequest", new UserRequest());

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }
        response.put("keycloakRealm", keycloakRealm);

        return ResponseEntity.ok(response);
    }

    /**
     * Maneja las solicitudes POST para procesar el registro de un nuevo usuario.
     * Recibe los datos de registro como JSON en el cuerpo de la solicitud.
     * Realiza una validación básica de contraseñas y luego delega la creación del usuario
     * a {@link KeycloakService}. Devuelve JSON con el estado de la operación.
     *
     * @param realm   El nombre del tenant extraído de la URL. Este `realm`
     *                se usará para cualquier lógica específica del cliente si fuera necesario,
     *                pero el registro de usuario se hace en el `singleKeycloakRealm` principal.
     * @param request El objeto {@link UserRequest} que contiene los datos del formulario de registro,
     *                recibido del cuerpo de la solicitud JSON.
     * @return Un {@link ResponseEntity} con el estado de éxito o error del registro.
     */
    @PostMapping("/{realm}/register")
    public ResponseEntity<Map<String, Object>> registerUser(@PathVariable String realm, @Valid @RequestBody UserRequest request) {
        log.info("Intento de registro de usuario para el tenant: {}", realm);
        log.debug("Datos de registro recibidos: username={}, email={}", request.getUsername(), request.getEmail());

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenant: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }

        if (keycloakService.userExistsByEmail(keycloakRealm, request.getEmail())) {
            log.warn("El email '{}' ya esta registrado en el realm '{}'.", request.getEmail(), keycloakRealm);
            throw new IllegalArgumentException("El email '" + request.getEmail() + "' ya está registrado.");
        }

        userService.registerUser(realm, request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "User registered. Waiting for admin approval.");
        response.put("tenantId", realm);
        response.put("keycloakRealm", keycloakRealm);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Endpoint para obtener la lista de todos los usuarios en un realm.
     *
     * @param realm El nombre del realm (tenant).
     * @return Una lista de {@link UserRepresentation} con los usuarios.
     */
    @GetMapping
    public ResponseEntity<List<UserRepresentation>> getAllUsers(@PathVariable String realm) {
        log.info("Solicitud para obtener todos los usuarios del tenant: {}", realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }

        List<UserRepresentation> users = keycloakService.getAllUsers(keycloakRealm);
        return ResponseEntity.ok(users);
    }

    /**
     * Endpoint para actualizar un usuario por su ID.
     *
     * @param realm       El nombre del realm (tenant).
     * @param userId      El ID del usuario a actualizar.
     * @param updatedUser Los datos del usuario actualizados.
     * @return Una respuesta vacía con estado OK.
     */
    @PutMapping("/{userId}")
    public ResponseEntity<Void> updateUser(@PathVariable String realm, @PathVariable UUID userId, @RequestBody UserRequest updatedUser) {
        log.info("Solicitud para actualizar el usuario con ID '{}' del tenant: {}", userId, realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }

        keycloakService.updateUser(keycloakRealm, userId.toString(), updatedUser);
        return ResponseEntity.ok().build();
    }

    /**
     * Endpoint para eliminar un usuario por su ID.
     *
     * @param realm  El nombre del realm (tenant).
     * @param userId El ID del usuario a eliminar.
     * @return Una respuesta vacía con estado NO_CONTENT.
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable String realm, @PathVariable UUID userId) {
        log.info("Solicitud para eliminar el usuario con ID '{}' del tenant: {}", userId, realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }

        keycloakService.deleteUser(keycloakRealm, userId.toString());
        return ResponseEntity.noContent().build();
    }
}
