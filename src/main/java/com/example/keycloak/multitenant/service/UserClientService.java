package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserWithDetailedClientRoles;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.service.keycloak.KeycloakClientUserService;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de alto nivel para la gestion de usuarios con enfoque en roles de cliente.
 * Este servicio orquesta operaciones de registro, actualizacion, y consulta,
 * delegando toda la interaccion con Keycloak a KeycloakClientUserService.
 */
@Service
public class UserClientService {

    private static final Logger log = LoggerFactory.getLogger(UserClientService.class);
    private final KeycloakClientUserService keycloakClientUserService;
    private final RegistrationFlowService registrationFlowService;

    public UserClientService(KeycloakClientUserService keycloakClientUserService,
                             RegistrationFlowService registrationFlowService) {
        this.keycloakClientUserService = keycloakClientUserService;
        this.registrationFlowService = registrationFlowService;
        log.info("UserClientService inicializado.");
    }

    /**
     * Obtiene una lista de todos los usuarios de un tenant, incluyendo sus roles de cliente.
     *
     * @param realm El nombre público del tenant.
     * @return Una lista de {@link UserWithRoles} con los detalles de cada usuario.
     */
    public List<UserWithDetailedClientRoles> getAllUsersWithClientRoles(String realm) {
        log.info("Procesando la solicitud para obtener todos los usuarios del tenant '{}' con roles.", realm);
        List<UserWithDetailedClientRoles> users = keycloakClientUserService.getAllUsersWithRoles(realm);
        log.info("Se han obtenido {} usuarios con sus roles.", users.size());
        return users;
    }

    /**
     * Obtiene la informacion de un usuario, incluyendo sus roles de cliente,
     * a partir de su ID y el nombre del tenant.
     *
     * @param realm  El nombre público del tenant.
     * @param userId El ID único del usuario en Keycloak.
     * @return Un objeto {@link UserWithDetailedClientRoles} que contiene los detalles del usuario
     * y una lista de sus roles.
     */
    public UserWithDetailedClientRoles getUserById(String realm, String userId) {
        log.info("Procesando la solicitud para obtener detalles del usuario con ID '{}' del tenant '{}'.", userId, realm);
        UserWithDetailedClientRoles userDetails = keycloakClientUserService.getUserByIdWithClientRoles(realm, userId);
        log.debug("Detalles de usuario obtenidos exitosamente para el ID '{}'.", userId);
        return userDetails;
    }

    /**
     * Genera una contrasena temporal segura de 12 caracteres.
     *
     * @return La contrasena temporal generada.
     */
    private String generateTemporaryPassword() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_";
        Random random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        log.debug("Contrasena temporal de 12 caracteres generada exitosamente.");
        return sb.toString();
    }

    public UserWithDetailedClientRoles getUserByEmailWithClientRoles(String realm, String clientId, String email) {
        return null;
    }
}