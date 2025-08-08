package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.UserRequest;
import java.security.SecureRandom;
import java.util.Random;
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
     * @param realmPath
     * @param request
     */
    public void registerUser(String realmPath, UserRequest request) {
        log.info("Procesando registro para el realm: {}", realmPath);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realmPath);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realmPath);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realmPath + " no reconocido.");
        }

        Assert.hasText(request.getRole(), "El rol no puede estar vacio");

        if (keycloakService.userExistsByEmail(keycloakRealm, request.getEmail())) {
            log.warn("Error de registro: El email'{}' ya esta registrado en el realm '{}'.", request.getEmail(), realm);
            throw new IllegalArgumentException("El email '" + request.getEmail() + "' ya está registrado.");
        }

        String tempPassword = generateTemporaryPassword();
        keycloakService.createUserWithRole(keycloakRealm, request, tempPassword);

        log.info("Usuario '{}' registrado exitosamente en el realm Keycloak '{}' para el tenant '{}'.", request.getUsername(), keycloakRealm, realm);
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
}
