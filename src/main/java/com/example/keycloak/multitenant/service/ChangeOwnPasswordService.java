package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.service.keycloak.KeycloakChangeOwnPasswordService;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUserService;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Servicio para gestionar el cambio de contraseña de un usuario.
 * Sigue el flujo de validar la contraseña actual antes de permitir el cambio,
 * orquestando las llamadas a los servicios de autenticación y de usuario.
 *
 * @author Angel Fm
 * @version 1.0
 * @see LoginService
 * @see KeycloakUserService
 * @see KeycloakAdminService
 */
@Service
public class ChangeOwnPasswordService {

    private static final Logger log = LoggerFactory.getLogger(ChangeOwnPasswordService.class);

    private final KeycloakChangeOwnPasswordService keycloakChangeOwnPasswordService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakChangeOwnPasswordService El servicio de bajo nivel para ejecutar la lógica de Keycloak.
     */
    public ChangeOwnPasswordService(KeycloakChangeOwnPasswordService keycloakChangeOwnPasswordService) {
        this.keycloakChangeOwnPasswordService = keycloakChangeOwnPasswordService;
    }

    /**
     * Permite a un usuario cambiar su propia contraseña verificando la actual.
     * <p>
     * Se encarga de las validaciones de negocio de alto nivel y delega la ejecución al servicio
     * de Keycloak.
     *
     * @param realm           El nombre del realm (tenant).
     * @param client          El ID del cliente de Keycloak.
     * @param userId          El ID del usuario cuya contraseña se va a cambiar.
     * @param username        El nombre de usuario.
     * @param currentPassword La contraseña actual a verificar.
     * @param newPassword     La nueva contraseña.
     */
    public void changeOwnPassword(String realm, String client, String userId, String username, String currentPassword, String newPassword) {
        log.info("Iniciando el cambio de contraseña para el usuario '{}' en el realm '{}'.", username, realm);

        if (currentPassword == null || currentPassword.isEmpty() || newPassword == null || newPassword.isEmpty()) {
            log.error("Password actual o nueva esta vacía.");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La password actual y la nueva no pueden estar vacías.");
        }

        keycloakChangeOwnPasswordService.changePassword(realm, client, userId, username, currentPassword, newPassword);
        log.info("Orquestador finalizado. La operación de cambio de contraseña para el usuario '{}' ha sido exitosa.", username);
    }
}
