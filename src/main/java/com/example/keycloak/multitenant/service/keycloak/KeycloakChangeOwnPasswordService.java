package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.service.LoginService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio de bajo nivel para ejecutar la lógica de cambio de contraseña.
 * Encapsula la interacción con los servicios de autenticación y de usuario de Keycloak
 * para realizar la operación de forma segura.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakChangeOwnPasswordService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakChangeOwnPasswordService.class);

    private final LoginService loginService;
    private final KeycloakUserService keycloakUserService;

    public KeycloakChangeOwnPasswordService(LoginService loginService, KeycloakUserService keycloakUserService) {
        this.loginService = loginService;
        this.keycloakUserService = keycloakUserService;
        log.info("KeycloakChangeOwnPasswordService inicializado.");
    }

    /**
     * Realiza el flujo completo de "login y cambio de contraseña" para un usuario.
     * Este método se encarga de la lógica de negocio de bajo nivel:
     * 1. Autenticar con la contraseña actual.
     * 2. Obtener el recurso de usuario a través del cliente de administración.
     * 3. Llamar al servicio de usuario para realizar el reset de contraseña.
     *
     * @param realm           El nombre del realm (tenant).
     * @param client          El ID del cliente de Keycloak.
     * @param userId          El ID del usuario cuya contraseña se va a cambiar.
     * @param username        El nombre de usuario.
     * @param currentPassword La contraseña actual a verificar.
     * @param newPassword     La nueva contraseña.
     */
    public void changePassword(String realm, String client, String userId, String username, String currentPassword, String newPassword) {
        log.info("Iniciando la operación de cambio de contraseña a nivel de Keycloak para el usuario '{}'.", username);

        try {
            loginService.authenticate(realm, client, username, currentPassword);
            log.debug("Validación de contraseña actual exitosa para el usuario '{}'.", username);
        } catch (ResponseStatusException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.warn("La contraseña actual proporcionada para el usuario '{}' es incorrecta.", username);
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Password actual incorrecta.");
            }
            throw e;
        }

        try {
            keycloakUserService.resetUserPassword(realm, userId, newPassword);
            log.info("Contraseña cambiada exitosamente para el usuario '{}'.", username);
        } catch (NotFoundException e) {
            log.error("Usuario con ID '{}' no encontrado durante el cambio de contraseña.", userId, e);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado con ID: " + userId);
        } catch (WebApplicationException e) {
            log.error("Fallo la comunicación con Keycloak al cambiar la contraseña del usuario '{}': Status = {}", userId, e.getResponse().getStatus(), e);
            throw new ResponseStatusException(e.getResponse().getStatus(), "Fallo al cambiar la contraseña.", e);
        }
    }
}
