package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUserService;
import com.example.keycloak.multitenant.service.mail.MailService;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Value;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio de alto nivel para la gestión de usuarios, interactuando con la capa de Keycloak.
 * Encapsula la lógica de negocio, como la validación de la existencia de usuarios por email,
 * la generación de contraseñas temporales y la orquestación de la creación, actualización
 * y eliminación de usuarios.
 *
 * @author Angel Fm
 * @version 1.1
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private final KeycloakUserService keycloakUserService;
    private final RegistrationFlowService registrationFlowService;

    @Value("${app.base-url}")
    private String baseUrl;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param keycloakUserService     Servicio de bajo nivel para operaciones CRUD en Keycloak.
     * @param registrationFlowService Servicio de token y email
     */
    public UserService(KeycloakUserService keycloakUserService, RegistrationFlowService registrationFlowService) {
        this.keycloakUserService = keycloakUserService;
        this.registrationFlowService = registrationFlowService;
        log.info("UserService inicializado.");
    }

    /**
     * Procesa el registro de un nuevo usuario, incluyendo validaciones y la creación
     * en Keycloak con una contraseña temporal.
     *
     * @param realmPath El nombre del tenant (ruta de realm) de la aplicación.
     * @param request   Los datos del usuario a registrar, encapsulados en un {@link UserRequest}.
     * @return Un mapa con los detalles de la respuesta de registro, incluyendo un mensaje,
     * el tenantId y el realm de Keycloak.
     * @throws ResponseStatusException  Si el tenant (realm) no es reconocido.
     * @throws IllegalArgumentException Si el email del usuario ya está registrado en el realm.
     */
    public Map<String, Object> registerUser(String realmPath, UserRequest request) {
        log.info("Procesando registro para el realm: {}", realmPath);
        log.debug("Datos de registro recibidos: username={}, email={}", request.username(), request.email());

        if (keycloakUserService.userExistsByEmail(realmPath, request.email())) {
            log.warn("Error de registro: El email'{}' ya esta registrado en el realm '{}'.", request.email(), realmPath);
            throw new IllegalArgumentException("El email '" + request.email() + "' ya está registrado.");
        }

        String tempPassword = generateTemporaryPassword();
        String userId = keycloakUserService.createUserWithRole(realmPath, request, tempPassword);

        registrationFlowService.startSetPasswordFlow(realmPath, userId, request);

        log.info("Usuario '{}' registrado exitosamente en el realm '{}'.", request.username(), realmPath);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Usuario registrado. Esperando aprobacion de administrador.");
        response.put("tenantId", realmPath);
        response.put("keycloakRealm", realmPath);

        return response;
    }

    public void enableAndVerifyEmail(String realm, String userId) {
        log.info("Habilitando usuario '{}' y marcando email como verificado en realm '{}'.", userId, realm);
        keycloakUserService.enableUserAndVerifyEmail(realm, userId);
    }


    /**
     * Genera una contraseña temporal segura de 12 caracteres utilizando una mezcla
     * de letras mayúsculas, minúsculas, números y caracteres especiales.
     *
     * @return La contraseña temporal generada.
     */
    private String generateTemporaryPassword() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_";
        Random random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        log.debug("Contraseña temporal de 12 caracteres generada exitosamente.");
        return sb.toString();
    }

    /**
     * Obtiene una lista de todos los usuarios de un tenant, incluyendo sus roles.
     * <p>
     * Este método actúa como una capa de servicio, resolviendo el realm
     * de Keycloak y delegando la obtención de datos a la capa de bajo nivel.
     *
     * @param realm El nombre público del tenant.
     * @return Una lista de {@link UserWithRoles} con los detalles de cada usuario.
     */
    public List<UserWithRoles> getAllUsers(String realm) {
        log.info("Procesando la solicitud para obtener todos los usuarios del tenant '{}'.", realm);

        List<UserWithRoles> users = keycloakUserService.getAllUsersWithRoles(realm);

        log.info("Se han obtenido {} usuarios con sus roles del tenant '{}'.", users.size(), realm);
        return users;
    }

    /**
     * Actualiza un usuario existente en un realm de Keycloak.
     *
     * @param realm       El nombre del tenant.
     * @param userId      El ID del usuario a actualizar.
     * @param updatedUser Los datos de usuario a actualizar, encapsulados en un {@link UserRequest}.
     * @throws ResponseStatusException Si el tenant no es reconocido.
     */
    public void updateUser(String realm, String userId, UserRequest updatedUser) {
        log.info("Iniciando la actualización para el usuario con ID '{}' en el tenant '{}'.", userId, realm);
        keycloakUserService.updateUser(realm, userId, updatedUser);
        log.info("Usuario con ID '{}' actualizado exitosamente.", userId);
    }

    /**
     * Elimina un usuario de un realm de Keycloak por su ID.
     *
     * @param realm  El nombre del tenant.
     * @param userId El ID del usuario a eliminar.
     * @throws ResponseStatusException Si el tenant no es reconocido.
     */
    public void deleteUser(String realm, String userId) {
        log.info("Iniciando la eliminación para el usuario con ID '{}' del tenant '{}'.", userId, realm);
        keycloakUserService.deleteUser(realm, userId);
        log.info("Usuario con ID '{}' eliminado exitosamente.", userId);
    }

    /**
     * Obtiene la información de un usuario, incluyendo sus roles,
     * a partir de su ID y el nombre del tenant.
     * <p>
     * Este método actúa como una capa de servicio, resolviendo el realm
     * de Keycloak y delegando la lógica de recuperación de datos a
     * {@link KeycloakUserService}.
     *
     * @param realm  El nombre público del tenant.
     * @param userId El ID único del usuario en Keycloak.
     * @return Un objeto {@link UserWithRoles} que contiene los detalles del usuario
     * y una lista de sus roles.
     * @throws org.springframework.web.server.ResponseStatusException si el tenant
     *                                                                no es reconocido.
     */
    public UserWithRoles getUserById(String realm, String userId) {
        log.info("Procesando la solicitud para obtener detalles del usuario con ID '{}' en el tenant '{}'.", userId, realm);

        UserWithRoles userDetails = keycloakUserService.getUserByIdWithRoles(realm, userId);

        log.debug("Detalles de usuario obtenidos exitosamente para el ID '{}'.", userId);
        return userDetails;
    }

    /**
     * Obtiene la información de un usuario, incluyendo sus roles,
     * a partir de su email y el nombre del tenant.
     *
     * @param realm El nombre público del tenant.
     * @param email El correo electrónico del usuario.
     * @return Un objeto {@link UserWithRoles} que contiene los detalles del usuario y una lista de sus roles.
     * @throws ResponseStatusException si el tenant no es reconocido.
     */
    public UserWithRoles getUserByEmail(String realm, String email) {
        log.info("Procesando la solicitud para obtener detalles del usuario con email '{}' en el realm '{}'.", email, realm);

        UserWithRoles userDetails = keycloakUserService.getUserByEmailWithRoles(realm, email);

        log.debug("Detalles de usuario obtenidos exitosamente para el email '{}'.", email);
        return userDetails;
    }

    /**
     * Busca usuarios por atributos personalizados dentro de un tenant específico.
     * Delega la búsqueda a la capa de servicio de Keycloak y maneja la resolución del realm.
     *
     * @param realm    El nombre del tenant (realm) a buscar.
     * @param criteria Los criterios de búsqueda (organización, filial, departamento).
     * @return Una lista de usuarios que coinciden con los criterios.
     */
    public List<UserWithRolesAndAttributes> getUsersByAttributes(String realm, UserSearchCriteria criteria) {
        log.info("Iniciando la búsqueda de usuarios por atributos para el tenant '{}'.", realm);

        List<UserWithRolesAndAttributes> users = keycloakUserService.getUsersByAttributes(realm, criteria);

        log.info("Búsqueda completada. Se encontraron {} usuarios.", users.size());
        return users;
    }

    /**
     * Restablece la contrasena de un usuario en un realm especifico.
     * <p>
     * Este metodo anade logica de negocio antes de delegar la llamada a la capa de
     * interaccion con Keycloak. Por ejemplo, valida que la nueva contrasena no este
     * vacia.
     *
     * @param realm       El nombre publico del tenant.
     * @param userId      El ID unico del usuario en Keycloak.
     * @param newPassword La nueva contrasena para el usuario.
     * @throws IllegalArgumentException Si la nueva contrasena es nula o esta vacia.
     * @throws ResponseStatusException  Si el tenant no es reconocido.
     */
    public void resetUserPassword(String realm, String userId, String newPassword) {
        log.info("Iniciando la solicitud de restablecimiento de contrasena para el usuario con ID '{}' en el tenant '{}'.", userId, realm);

        if (newPassword == null || newPassword.isBlank()) {
            log.warn("Error de validacion: La nueva contrasena no puede ser nula o vacia para el usuario '{}'.", userId);
            throw new IllegalArgumentException("La nueva contrasena no puede estar vacia.");
        }

        keycloakUserService.resetUserPassword(realm, userId, newPassword);

        log.info("Contrasena restablecida exitosamente para el usuario con ID '{}'.", userId);
    }


}
