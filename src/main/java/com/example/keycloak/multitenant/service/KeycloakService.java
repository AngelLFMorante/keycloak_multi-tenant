package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.model.UserRequest;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para interactuar con la API de administración de Keycloak.
 * Proporciona métodos para realizar operaciones administrativas, como la creación de usuarios,
 * en un realm específico de Keycloak.
 */
@Service
public class KeycloakService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakService.class);

    /**
     * Cliente de administración de Keycloak, inyectado automáticamente.
     * Este cliente se utiliza para realizar llamadas a la API REST de administración de Keycloak.
     */
    private final Keycloak keycloak;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloak Instancia del cliente de administración de Keycloak.
     */
    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
        log.info("KeycloakService inicializado.");
    }

    /**
     * Crea un nuevo usuario en un realm de Keycloak, asigna una contraseña temporal y un rol.
     *
     * @param realm        El nombre del realm de Keycloak.
     * @param request      Los datos del usuario a registrar.
     * @param tempPassword La contraseña temporal generada.
     */
    public void createUserWithRole(String realm, UserRequest request, String tempPassword) {
        log.info("Iniciando el proceso de registro para el usuario '{}' en el realm '{}'.", request.getUsername(), realm);

        RealmResource realmResource = keycloak.realm(realm);

        String userId = createUser(realmResource, request);
        setTemporaryPassword(realmResource, userId, tempPassword);
        assignRoleToUser(realmResource, userId, request.getRole());

        log.info("Usuario '{}' registrado exitosamente con el rol '{}'.", request.getUsername(), request.getRole());
    }

    /**
     * Comprueba si un usuario con el email dado ya existe en Keycloak.
     *
     * @param realm El nombre del realm de Keycloak a consultar.
     * @param email El email a buscar.
     * @return {@code true} si el email ya está en uso, de lo contrario {@code false}.
     */
    public boolean userExistsByEmail(String realm, String email) {
        log.debug("Comprobando si el email '{}' ya existe en el realm '{}'.", email, realm);
        List<UserRepresentation> users = keycloak.realm(realm).users().searchByEmail(email, true);
        return users != null && !users.isEmpty();
    }

    /**
     * Obtiene una lista de todos los usuarios en un realm específico.
     *
     * @param realm El nombre del realm de Keycloak.
     * @return Una lista de {@link UserRepresentation} de todos los usuarios.
     */
    public List<UserRepresentation> getAllUsers(String realm) {
        log.info("Obteniendo todos los usuarios del realm '{}'.", realm);
        return keycloak.realm(realm).users().list();
    }

    /**
     * Actualiza la información de un usuario existente en un realm, modificando solo los campos proporcionados.
     *
     * @param realm              El nombre del realm de Keycloak.
     * @param userId             El ID del usuario a actualizar.
     * @param updatedUserRequest Los datos de usuario actualizados, recibidos del controlador.
     */
    public void updateUser(String realm, String userId, UserRequest updatedUserRequest) {
        log.info("Actualizando usuario con ID '{}' en el realm '{}'.", userId, realm);

        RealmResource realmResource = keycloak.realm(realm);
        UserResource userResource = realmResource.users().get(userId);

        UserRepresentation userRepresentation = userResource.toRepresentation();

        if (updatedUserRequest.getFirstName() != null && !updatedUserRequest.getFirstName().isBlank()) {
            userRepresentation.setFirstName(updatedUserRequest.getFirstName());
        }
        if (updatedUserRequest.getLastName() != null && !updatedUserRequest.getLastName().isBlank()) {
            userRepresentation.setLastName(updatedUserRequest.getLastName());
        }
        if (updatedUserRequest.getEmail() != null && !updatedUserRequest.getEmail().isBlank()) {
            userRepresentation.setEmail(updatedUserRequest.getEmail());
        }
        if (updatedUserRequest.getUsername() != null && !updatedUserRequest.getUsername().isBlank()) {
            userRepresentation.setUsername(updatedUserRequest.getUsername());
        }

        userResource.update(userRepresentation);

        log.info("Usuario con ID '{}' actualizado exitosamente.", userId);
    }

    /**
     * Elimina un usuario por su ID en un realm específico.
     *
     * @param realm  El nombre del realm de Keycloak.
     * @param userId El ID del usuario a eliminar.
     */
    public void deleteUser(String realm, String userId) {
        log.info("Eliminando usuario con ID '{}' del realm '{}'.", userId, realm);
        keycloak.realm(realm).users().get(userId).remove();
        log.info("Usuario con ID '{}' eliminado exitosamente.", userId);
    }

    private String createUser(RealmResource realmResource, UserRequest request) {
        log.debug("Creando usuario '{}' en Keycloak.", request.getUsername());
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEnabled(false);

        try (Response response = realmResource.users().create(user)) {
            if (response.getStatus() != 201) {
                String errorDetails = response.readEntity(String.class);
                log.error("Fallo al crear usuario '{}'. Estado: {}, Detalles: {}", request.getUsername(), response.getStatus(), errorDetails);
                throw new KeycloakUserCreationException("Error al crear usuario. Estado HTTP: " + response.getStatus() + ". Detalles: " + errorDetails);
            }
            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            log.info("Usuario '{}' creado exitosamente con ID: {}.", request.getUsername(), userId);
            return userId;
        } catch (Exception e) {
            log.error("Excepción inesperada al crear usuario: {}", e.getMessage());
            throw new KeycloakUserCreationException("Error inesperado al crear usuario: " + e.getMessage(), e);
        }
    }

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

    private void assignRoleToUser(RealmResource realmResource, String userId, String roleName) {
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

    /**
     * Crea un nuevo rol en un realm especifico de Keycloak
     *
     * @param realm   realm keycloak
     * @param request datos del crear role
     */
    public void createRole(String realm, CreateRoleRequest request) {
        log.info("Intentando crear el rol '{}' en el realm '{}'.", request.getName(), realm);
        log.debug("Datos del rol para creación: nombre='{}', descripción='{}'", request.getName(), request.getDescription());

        RoleRepresentation role = new RoleRepresentation();
        role.setName(request.getName());
        role.setDescription(request.getDescription());
        role.setClientRole(false); //rol de realm no de cliente

        RealmResource realmResource = keycloak.realm(realm);

        boolean rolExist = realmResource.roles().list().stream().anyMatch(
                r -> r.getName().equals((role.getName())));

        if (!rolExist) {
            try {
                realmResource.roles().create(role);
            } catch (WebApplicationException e) {

                Response response = e.getResponse();
                String errorMessage;

                if (response != null) {
                    int statusCode = response.getStatus();
                    errorMessage = response.readEntity(String.class);

                    log.error("Error al crear el rol '{}'. Estado HTTP: {}, Detalles: {}", request.getName(), statusCode, errorMessage);
                    throw new KeycloakRoleCreationException("Error al crear el rol en Keycloak. Estado HTTP: " + statusCode + ". Detalles: " + errorMessage);
                }

                log.error("Error inesperado al intentar crear el rol '{}' en Keycloak: {}", request.getName(), e.getMessage(), e);
                throw new RuntimeException("Error inesperado al crear el rol: " + e.getMessage(), e);

            } catch (Exception e) {
                log.error("Exception inesperado al intentar crear el rol '{}' en Keycloak: {}", request.getName(), e.getMessage(), e);
                throw new RuntimeException("Error inesperado al crear el rol: " + e.getMessage(), e);
            }
        } else {
            log.error("Fallo, role '{}' ya existe en Keycloak.", request.getName());
            throw new KeycloakRoleCreationException("El rol '" + request.getName() + "' ya existe en el realm '" + realm + "'.");
        }
    }

    /**
     * Elimina un rol por su nombre en un realm especifico de keycloak
     *
     * @param realm    El nombre del realm de Keycloak donde se eliminará el rol.
     * @param roleName El nombre del rol a eliminar.
     * @throws RuntimeException  Si la eliminación del rol falla en Keycloak.
     * @throws NotFoundException Si el rol no se encuentra.
     */
    public void deleteRole(String realm, String roleName) {
        log.info("Intentando eliminar el rol '{}' del realm '{}'.", roleName, realm);

        RealmResource realmResource = keycloak.realm(realm);
        boolean rolExist = realmResource.roles().list().stream().anyMatch(
                r -> r.getName().equals(roleName));

        if (rolExist) {
            try {
                realmResource.roles().deleteRole(roleName);
            } catch (Exception e) {
                log.error("Excepción inesperada al intentar eliminar el rol '{}' del realm '{}': {}", roleName, realm, e.getMessage(), e);
                throw new RuntimeException("Error inesperado al eliminar el rol: " + e.getMessage(), e);
            }
        } else {
            log.warn("El rol '{}' no fue encontrado en el realm '{}' para eliminación.", roleName, realm);
            throw new NotFoundException("Rol '" + roleName + "' no encontrado en el realm '" + realm + "'.");
        }
    }

    /**
     * Obtiene una lista de todos los roles de realm disponibles en un realm específico de Keycloak.
     *
     * @param realm El nombre del realm de Keycloak a consultar.
     * @return Una lista de objetos {@link RoleRepresentation} que representan los roles.
     * @throws RuntimeException Si la obtención de roles falla en Keycloak.
     */
    public List<RoleRepresentation> getRoles(String realm) {
        log.info("Intentando obtener todos los roles del realm '{}'.", realm);

        RealmResource realmResource = keycloak.realm(realm);

        try {
            List<RoleRepresentation> roles = realmResource.roles().list();
            log.info("Se obtuvieron {} roles del realm '{}'.", roles.size(), realm);
            return roles;
        } catch (Exception e) {
            log.error("Excepción inesperada al intentar obtener roles del realm '{}': {}", realm, e.getMessage(), e);
            throw new RuntimeException("Error inesperado al obtener roles: " + e.getMessage(), e);
        }
    }
}
