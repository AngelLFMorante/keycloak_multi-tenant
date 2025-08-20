package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.UserRequest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.server.ResponseStatusException;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private final KeycloakService keycloakService;
    private final KeycloakProperties keycloakProperties;

    public UserService(KeycloakService keycloakService, KeycloakProperties keycloakProperties) {
        this.keycloakService = keycloakService;
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Procesa el registro de un nuevo usuario, incluyendo validaciones y la creación
     * en Keycloak con una contraseña temporal.
     *
     * @param realmPath El nombre del tenant.
     * @param request   Los datos del usuario a registrar.
     * @return Un mapa con los detalles de la respuesta de registro.
     */
    public Map<String, Object> registerUser(String realmPath, UserRequest request) {
        log.info("Procesando registro para el realm: {}", realmPath);
        log.debug("Datos de registro recibidos: username={}, email={}", request.getUsername(), request.getEmail());

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realmPath);

        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realmPath);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realmPath + " no reconocido.");
        }

        if (keycloakService.userExistsByEmail(keycloakRealm, request.getEmail())) {
            log.warn("Error de registro: El email'{}' ya esta registrado en el realm '{}'.", request.getEmail(), realmPath);
            throw new IllegalArgumentException("El email '" + request.getEmail() + "' ya está registrado.");
        }

        String tempPassword = generateTemporaryPassword();
        keycloakService.createUserWithRole(keycloakRealm, request, tempPassword);

        log.info("Usuario '{}' registrado exitosamente en el realm Keycloak '{}' para el tenant '{}'.", request.getUsername(), keycloakRealm, realmPath);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Usuario registrado. Esperando aprobacion de administrador.");
        response.put("tenantId", realmPath);
        response.put("keycloakRealm", keycloakRealm);

        return response;
    }

    /**
     * @return
     */
    private String generateTemporaryPassword() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_";
        Random random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * Obtiene todos los usuarios de un realm.
     *
     * @param realm El nombre del tenant.
     * @return Una lista de representaciones de usuario.
     */
    public List<UserRepresentation> getAllUsers(String realm) {
        String keycloakRealm = getKeycloakRealm(realm);
        return keycloakService.getAllUsers(keycloakRealm);
    }

    private String getKeycloakRealm(String realmPath) {
        String keycloakRealm = keycloakProperties.getRealmMapping().get(realmPath);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenant: {}", realmPath);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realmPath + " no reconocido.");
        }
        return keycloakRealm;
    }

    /**
     * Actualiza un usuario en un realm.
     *
     * @param realm       El nombre del tenant.
     * @param userId      El ID del usuario.
     * @param updatedUser Los datos de usuario a actualizar.
     */
    public void updateUser(String realm, String userId, UserRequest updatedUser) {
        String keycloakRealm = getKeycloakRealm(realm);
        keycloakService.updateUser(keycloakRealm, userId, updatedUser);
    }

    /**
     * Elimina un usuario de un realm.
     *
     * @param realm  El nombre del tenant.
     * @param userId El ID del usuario.
     */
    public void deleteUser(String realm, String userId) {
        String keycloakRealm = getKeycloakRealm(realm);
        keycloakService.deleteUser(keycloakRealm, userId);
    }
}
