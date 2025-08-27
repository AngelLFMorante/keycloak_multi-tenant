package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de bajo nivel para interactuar directamente con la API de administracion de Keycloak
 * y gestionar las operaciones relacionadas con los usuarios.
 * <p>
 * Este servicio encapsula la logica de comunicacion con el cliente de administracion de Keycloak
 * para operaciones como la creacion, obtencion, actualizacion y eliminacion de usuarios.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakUserService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUserService.class);
    private final KeycloakRoleService keycloakRoleService;
    private final KeycloakAdminService utilsAdminService;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param keycloakRoleService Servicio para operaciones relacionadas con roles.
     * @param utilsAdminService   Servicio de utilidades para obtener recursos de Keycloak.
     */
    public KeycloakUserService(KeycloakRoleService keycloakRoleService, KeycloakAdminService utilsAdminService) {
        this.keycloakRoleService = keycloakRoleService;
        this.utilsAdminService = utilsAdminService;
        log.info("KeycloakUserService inicializado.");
    }

    /**
     * Obtiene una lista de todos los usuarios en un realm especifico.
     *
     * @param realm El nombre del realm de Keycloak.
     * @return Una lista de {@link UserRepresentation} de todos los usuarios.
     * @throws RuntimeException si el realm no se encuentra o hay un error de comunicacion.
     */
    public List<UserRepresentation> getAllUsers(String realm) {
        log.info("Obteniendo todos los usuarios del realm '{}'.", realm);
        try {
            return utilsAdminService.getRealmResource(realm).users().list();
        } catch (WebApplicationException e) {
            log.error("Error al obtener usuarios del realm '{}': Status={}", realm, e.getResponse().getStatus(), e);
            throw new RuntimeException("Error al obtener usuarios del realm '" + realm + "'. Detalles: " + e.getMessage());
        }
    }

    /**
     * Crea un nuevo usuario en un realm de Keycloak, asigna una contrasena temporal y un rol.
     * <p>
     * Este metodo coordina la creacion del usuario, el establecimiento de la contrasena
     * y la asignacion de roles en una sola operacion.
     *
     * @param realm        El nombre del realm de Keycloak.
     * @param request      Los datos del usuario a registrar.
     * @param tempPassword La contrasena temporal generada.
     * @throws KeycloakUserCreationException Si la creacion o actualizacion del usuario falla.
     * @throws KeycloakRoleCreationException Si la asignacion del rol falla.
     */
    public void createUserWithRole(String keycloakRealm, String realm, UserRequest request, String tempPassword) {
        log.info("Iniciando el proceso de registro para el usuario '{}' en el realm '{}'.", request.username(), realm);

        try {
            RealmResource realmResource = utilsAdminService.getRealmResource(keycloakRealm);

            String userId = createUser(realmResource, request);
            setTemporaryPassword(realmResource, userId, tempPassword);
            keycloakRoleService.checkRole(realm, request);
            assignRoleToUser(realmResource, userId, request.role());

            log.info("Usuario '{}' creado y configurado exitosamente en el realm '{}'.", request.username(), realm);
        } catch (Exception e) {
            log.error("Fallo durante el proceso de creacion de usuario '{}'.", request.username());
            throw new KeycloakUserCreationException("Fallo durante el proceso de creacion de usuario: " + e.getMessage(), e);
        }
    }


    /**
     * Comprueba si un usuario con el email dado ya existe en Keycloak.
     *
     * @param realm El nombre del realm de Keycloak a consultar.
     * @param email El email a buscar.
     * @return {@code true} si el email ya esta en uso, de lo contrario {@code false}.
     */
    public boolean userExistsByEmail(String realm, String email) {
        log.debug("Comprobando si el email '{}' ya existe en el realm '{}'.", email, realm);
        List<UserRepresentation> users = utilsAdminService.getRealmResource(realm).users().searchByEmail(email, true);
        boolean exists = users != null && !users.isEmpty();
        if (exists) {
            log.info("El email '{}' ya esta en uso en el realm '{}'.", email, realm);
        } else {
            log.debug("El email '{}' no existe en el realm '{}'.", email, realm);
        }
        return exists;
    }

    /**
     * Actualiza la informacion de un usuario existente en un realm, modificando solo los campos proporcionados.
     *
     * @param realm              El nombre del realm de Keycloak.
     * @param userId             El ID del usuario a actualizar.
     * @param updatedUserRequest Los datos de usuario actualizados, recibidos del controlador.
     * @throws NotFoundException             Si el usuario no se encuentra.
     * @throws KeycloakUserCreationException Si la actualizacion falla.
     */
    public void updateUser(String realm, String userId, UserRequest updatedUserRequest) {
        log.info("Actualizando usuario con ID '{}' en el realm '{}'.", userId, realm);

        try {
            RealmResource realmResource = utilsAdminService.getRealmResource(realm);
            UserResource userResource = realmResource.users().get(userId);

            UserRepresentation userRepresentation = userResource.toRepresentation();

            if (updatedUserRequest.firstName() != null && !updatedUserRequest.firstName().isBlank()) {
                userRepresentation.setFirstName(updatedUserRequest.firstName());
            }
            if (updatedUserRequest.lastName() != null && !updatedUserRequest.lastName().isBlank()) {
                userRepresentation.setLastName(updatedUserRequest.lastName());
            }
            if (updatedUserRequest.email() != null && !updatedUserRequest.email().isBlank()) {
                userRepresentation.setEmail(updatedUserRequest.email());
            }

            userResource.update(userRepresentation);
            log.info("Usuario con ID '{}' actualizado exitosamente.", userId);
        } catch (NotFoundException e) {
            log.error("Usuario con ID '{}' no encontrado para actualizacion.", userId);
            throw new NotFoundException("Usuario no encontrado con ID: " + userId);
        } catch (WebApplicationException e) {
            log.error("Fallo la actualizacion del usuario con ID '{}': Status={}", userId, e.getResponse().getStatus(), e);
            throw new KeycloakUserCreationException("Error al actualizar el usuario: " + e.getMessage(), e);
        }
    }

    /**
     * Elimina un usuario por su ID en un realm especifico.
     *
     * @param realm  El nombre del realm de Keycloak.
     * @param userId El ID del usuario a eliminar.
     * @throws NotFoundException             Si el usuario no se encuentra.
     * @throws KeycloakUserCreationException Si la eliminacion falla.
     */
    public void deleteUser(String realm, String userId) {
        log.info("Eliminando usuario con ID '{}' del realm '{}'.", userId, realm);
        try {
            utilsAdminService.getRealmResource(realm).users().get(userId).remove();
            log.info("Usuario con ID '{}' eliminado exitosamente.", userId);
        } catch (NotFoundException e) {
            log.warn("Usuario con ID '{}' no encontrado, no se puede eliminar.", userId);
            throw new NotFoundException("Usuario no encontrado con ID: " + userId);
        } catch (WebApplicationException e) {
            log.error("Fallo al eliminar el usuario con ID '{}': Status={}", userId, e.getResponse().getStatus(), e);
            throw new KeycloakUserCreationException("Error al eliminar el usuario: " + e.getMessage(), e);
        }
    }

    // ---------------------- Private Helpers ----------------------

    /**
     * Crea un nuevo usuario en Keycloak y maneja la respuesta HTTP.
     *
     * @param realmResource El recurso del realm de Keycloak.
     * @param request       Los datos del usuario a crear.
     * @return El ID del usuario creado.
     * @throws KeycloakUserCreationException Si la creacion del usuario falla.
     */
    private String createUser(RealmResource realmResource, UserRequest request) {
        log.debug("Creando usuario '{}' en Keycloak.", request.username());
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEnabled(false);

        try (Response response = realmResource.users().create(user)) {
            if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
                log.error("Fallo al crear usuario '{}'. El nombre de usuario o email ya existen.", request.username());
                throw new KeycloakUserCreationException("El nombre de usuario o email ya existen.");
            }
            if (response.getStatus() != 201) {
                String errorDetails = response.readEntity(String.class);
                log.error("Fallo al crear usuario '{}'. Estado: {}, Detalles: {}", request.username(), response.getStatus(), errorDetails);
                throw new KeycloakUserCreationException("Error al crear usuario. Estado HTTP: " + response.getStatus() + ". Detalles: " + errorDetails);
            }
            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            log.info("Usuario '{}' creado exitosamente con ID: {}.", request.username(), userId);
            return userId;
        } catch (WebApplicationException e) {
            String errorDetails = e.getResponse().readEntity(String.class);
            log.error("Error de la aplicacion al crear usuario: Status={}, Detalles={}", e.getResponse().getStatus(), errorDetails, e);
            throw new KeycloakUserCreationException("Error al crear usuario. Detalles: " + errorDetails, e);
        } catch (Exception e) {
            log.error("Excepcion inesperada al crear usuario: {}", e.getMessage(), e);
            throw new KeycloakUserCreationException("Error inesperado al crear usuario: " + e.getMessage(), e);
        }
    }

    /**
     * Establece una contrasena temporal para un usuario.
     *
     * @param realmResource El recurso del realm.
     * @param userId        El ID del usuario.
     * @param tempPassword  La contrasena temporal.
     * @throws KeycloakUserCreationException Si falla el establecimiento de la contrasena.
     */
    private void setTemporaryPassword(RealmResource realmResource, String userId, String tempPassword) {
        log.debug("Estableciendo contraseña temporal para el usuario ID '{}'.", userId);
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(tempPassword);
        credential.setTemporary(true);

        try {
            realmResource.users().get(userId).resetPassword(credential);
            log.info("Contraseña temporal establecida para el usuario ID '{}'.", userId);
        } catch (Exception e) {
            log.error("Fallo al establecer la contraseña para el usuario ID '{}'. Error: {}", userId, e.getMessage(), e);
            throw new KeycloakUserCreationException("Error al establecer la contraseña: " + e.getMessage(), e);
        }
    }

    /**
     * Asigna un rol de nivel de realm a un usuario.
     *
     * @param realmResource El recurso del realm.
     * @param userId        El ID del usuario.
     * @param roleName      El nombre del rol a asignar.
     * @throws KeycloakRoleCreationException Si el rol no existe o si la asignacion falla.
     */
    private void assignRoleToUser(RealmResource realmResource, String userId, String roleName) {
        if (roleName == null || roleName.isBlank()) {
            log.info("No se asignó ningún rol porque el rol está vacío o no especificado.");
            return;
        }

        log.debug("Asignando el rol '{}' al usuario ID '{}'.", roleName, userId);
        try {
            RoleRepresentation roleRepresentation = realmResource.roles().get(roleName).toRepresentation();
            realmResource.users().get(userId).roles().realmLevel().add(List.of(roleRepresentation));
            log.info("Rol '{}' asignado exitosamente al usuario ID '{}'.", roleName, userId);
        } catch (NotFoundException e) {
            log.error("Fallo al asignar el rol: el rol '{}' no fue encontrado.", roleName);
            throw new KeycloakRoleCreationException("El rol '" + roleName + "' no existe en el realm.");
        } catch (Exception e) {
            log.error("Fallo al asignar el rol '{}' al usuario ID '{}'. Error: {}", roleName, userId, e.getMessage(), e);
            throw new KeycloakRoleCreationException("Error al asignar el rol '" + roleName + "'.");
        }
    }

}
