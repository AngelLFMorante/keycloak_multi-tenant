package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.user.UserRequest;
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
     * Procesa el registro de un nuevo usuario, incluyendo validaciones, creación en Keycloak
     * y la asignación de un rol de cliente.
     *
     * @param realmPath El nombre del tenant (ruta de realm).
     * @param clientId  El ID del cliente.
     * @param request   Los datos del usuario.
     * @return Un mapa con los detalles de la respuesta de registro.
     * @throws IllegalArgumentException Si el email del usuario ya está registrado.
     */
    public Map<String, Object> registerUser(String realmPath, String clientId, UserRequest request) {
        log.info("Procesando registro para el realm: {} y cliente: {}", realmPath, clientId);
        log.debug("Datos de registro recibidos: username={}, email={}", request.username(), request.email());

        if (keycloakClientUserService.userExistsByEmail(realmPath, request.email())) {
            log.warn("Error de registro: El email'{}' ya esta registrado en el realm '{}'.", request.email(), realmPath);
            throw new IllegalArgumentException("El email '" + request.email() + "' ya está registrado.");
        }

        String tempPassword = generateTemporaryPassword();
        String userId = keycloakClientUserService.createUser(realmPath, request, tempPassword);

        if (request.role() != null && !request.role().isBlank()) {
            keycloakClientUserService.assignClientRoleToUser(realmPath, clientId, userId, request.role());
            log.info("Rol de cliente '{}' asignado al nuevo usuario '{}'.", request.role(), userId);
        }

        registrationFlowService.startSetPasswordFlow(realmPath, userId, request);

        log.info("Usuario '{}' registrado exitosamente en el realm '{}' con ID '{}'.", request.username(), realmPath, userId);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Usuario registrado. Espere la aprobación del administrador.");
        response.put("userId", userId);
        response.put("realm", realmPath);
        response.put("clientId", clientId);
        response.put("clientRole", request.role());

        return response;
    }

    /**
     * Actualiza un usuario existente y su rol de cliente.
     *
     * @param realm       El nombre del tenant.
     * @param clientId    El ID del cliente.
     * @param userId      El ID del usuario a actualizar.
     * @param updatedUser Los datos de usuario a actualizar.
     */
    public void updateUser(String realm, String clientId, String userId, UserRequest updatedUser) {
        log.info("Iniciando la actualización para el usuario con ID '{}' en el tenant '{}' y cliente '{}'.", userId, realm, clientId);

        keycloakClientUserService.updateUser(realm, userId, updatedUser);

        if (updatedUser.role() != null && !updatedUser.role().isBlank()) {
            keycloakClientUserService.updateUserClientRoles(realm, clientId, userId, updatedUser.role());
        }

        log.info("Usuario con ID '{}' y sus roles de cliente actualizados exitosamente.", userId);
    }

    /**
     * Elimina un usuario de un realm de Keycloak por su ID.
     *
     * @param realm  El nombre del tenant.
     * @param userId El ID del usuario a eliminar.
     */
    public void deleteUser(String realm, String userId) {
        log.info("Iniciando la eliminación para el usuario con ID '{}' del tenant '{}'.", userId, realm);
        keycloakClientUserService.deleteUser(realm, userId);
        log.info("Usuario con ID '{}' eliminado exitosamente.", userId);
    }

    /**
     * Restablece la contrasena de un usuario en un realm especifico.
     *
     * @param realm       El nombre publico del tenant.
     * @param userId      El ID unico del usuario en Keycloak.
     * @param newPassword La nueva contrasena para el usuario.
     */
    public void resetUserPassword(String realm, String userId, String newPassword) {
        log.info("Iniciando la solicitud de restablecimiento de contrasena para el usuario con ID '{}' en el tenant '{}'.", userId, realm);

        if (newPassword == null || newPassword.isBlank()) {
            log.warn("Error de validacion: La nueva contrasena no puede ser nula o vacia para el usuario '{}'.", userId);
            throw new IllegalArgumentException("La nueva contrasena no puede estar vacia.");
        }

        keycloakClientUserService.resetUserPassword(realm, userId, newPassword);
        log.info("Contrasena restablecida exitosamente para el usuario con ID '{}'.", userId);
    }

    /**
     * Obtiene una lista de todos los usuarios de un tenant, incluyendo sus roles de cliente.
     *
     * @param realm    El nombre público del tenant.
     * @param clientId El ID del cliente al que pertenecen los roles.
     * @return Una lista de {@link UserWithRoles} con los detalles de cada usuario.
     */
    public List<UserWithRoles> getAllUsersWithClientRoles(String realm, String clientId) {
        log.info("Procesando la solicitud para obtener todos los usuarios del tenant '{}' con roles del cliente '{}'.", realm, clientId);
        List<UserWithRoles> users = keycloakClientUserService.getAllUsersWithClientRoles(realm, clientId);
        log.info("Se han obtenido {} usuarios con sus roles del cliente '{}'.", users.size(), clientId);
        return users;
    }

    /**
     * Obtiene la informacion de un usuario, incluyendo sus roles de cliente,
     * a partir de su ID y el nombre del tenant.
     *
     * @param realm    El nombre público del tenant.
     * @param clientId El ID del cliente al que pertenecen los roles.
     * @param userId   El ID único del usuario en Keycloak.
     * @return Un objeto {@link UserWithRoles} que contiene los detalles del usuario
     * y una lista de sus roles.
     */
    public UserWithRoles getUserByIdWithClientRoles(String realm, String clientId, String userId) {
        log.info("Procesando la solicitud para obtener detalles del usuario con ID '{}' en el cliente '{}' del tenant '{}'.", userId, clientId, realm);
        UserWithRoles userDetails = keycloakClientUserService.getUserByIdWithClientRoles(realm, clientId, userId);
        log.debug("Detalles de usuario obtenidos exitosamente para el ID '{}'.", userId);
        return userDetails;
    }

    /**
     * Obtiene la informacion de un usuario, incluyendo sus roles de cliente,
     * a partir de su email y el nombre del tenant.
     *
     * @param realm    El nombre público del tenant.
     * @param clientId El ID del cliente al que pertenecen los roles.
     * @param email    El correo electrónico del usuario.
     * @return Un objeto {@link UserWithRoles} que contiene los detalles del usuario y una lista de sus roles.
     */
    public UserWithRoles getUserByEmailWithClientRoles(String realm, String clientId, String email) {
        log.info("Procesando la solicitud para obtener detalles del usuario con email '{}' en el cliente '{}' del realm '{}'.", email, clientId, realm);
        UserWithRoles userDetails = keycloakClientUserService.getUserByEmailWithClientRoles(realm, clientId, email);
        log.debug("Detalles de usuario obtenidos exitosamente para el email '{}'.", email);
        return userDetails;
    }

    /**
     * Asigna un rol de cliente a un usuario.
     *
     * @param realm    El nombre del tenant.
     * @param clientId El ID del cliente.
     * @param userId   El ID del usuario.
     * @param roleName El nombre del rol de cliente a asignar.
     * @return Un mapa de respuesta con el resultado de la operacion.
     */
    public Map<String, Object> assignClientRoleToUser(String realm, String clientId, String userId, String roleName) {
        log.info("Iniciando la asignacion del rol '{}' al usuario '{}' en el cliente '{}' del realm '{}'.", roleName, userId, clientId, realm);
        keycloakClientUserService.assignClientRoleToUser(realm, clientId, userId, roleName);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol de cliente asignado exitosamente.");
        response.put("userId", userId);
        response.put("roleName", roleName);
        return response;
    }

    /**
     * Elimina un rol de cliente de un usuario.
     *
     * @param realm    El nombre del tenant.
     * @param clientId El ID del cliente.
     * @param userId   El ID del usuario.
     * @param roleName El nombre del rol de cliente a eliminar.
     * @return Un mapa de respuesta con el resultado de la operacion.
     */
    public Map<String, Object> removeClientRoleFromUser(String realm, String clientId, String userId, String roleName) {
        log.info("Iniciando la eliminacion del rol '{}' al usuario '{}' en el cliente '{}' del realm '{}'.", roleName, userId, clientId, realm);
        keycloakClientUserService.removeClientRoleFromUser(realm, clientId, userId, roleName);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol de cliente eliminado exitosamente.");
        response.put("userId", userId);
        response.put("roleName", roleName);
        return response;
    }

    /**
     * Actualiza el rol de cliente de un usuario.
     *
     * @param realm       El nombre del tenant.
     * @param clientId    El ID del cliente.
     * @param userId      El ID del usuario.
     * @param newRoleName El nombre del nuevo rol de cliente a asignar.
     * @return Un mapa de respuesta con el resultado de la operacion.
     */
    public Map<String, Object> updateUserClientRoles(String realm, String clientId, String userId, String newRoleName) {
        log.info("Iniciando la actualizacion del rol del usuario '{}' al rol '{}' en el cliente '{}' del realm '{}'.", userId, newRoleName, clientId, realm);
        keycloakClientUserService.updateUserClientRoles(realm, clientId, userId, newRoleName);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol de cliente actualizado exitosamente.");
        response.put("userId", userId);
        response.put("roleName", newRoleName);
        return response;
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
}