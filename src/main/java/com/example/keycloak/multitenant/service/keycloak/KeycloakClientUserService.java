package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de bajo nivel para la gestion de usuarios, roles de cliente, y
 * la interaccion con la API de administracion de Keycloak.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakClientUserService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakClientUserService.class);
    private final KeycloakAdminService utilsAdminService;
    private final KeycloakConfigService utilsConfigService;

    public KeycloakClientUserService(KeycloakAdminService utilsAdminService, KeycloakConfigService utilsConfigService) {
        this.utilsAdminService = utilsAdminService;
        this.utilsConfigService = utilsConfigService;
        log.info("KeycloakClientUserService inicializado.");
    }

    /**
     * Crea un nuevo usuario en un realm de Keycloak y devuelve su ID.
     *
     * @param realm        El nombre del realm de Keycloak.
     * @param request      Los datos del usuario a registrar.
     * @param tempPassword La contrasena temporal generada.
     * @return El ID del usuario recien creado.
     * @throws KeycloakUserCreationException Si la creacion del usuario falla.
     */
    public String createUser(String realm, UserRequest request, String tempPassword) {
        log.info("Creando usuario '{}' en el realm '{}'.", request.username(), realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEnabled(true);
        user.setEmailVerified(true);

        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(true);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(tempPassword);
        user.setCredentials(List.of(passwordCred));

        try (Response response = utilsAdminService.getRealmResource(keycloakRealm).users().create(user)) {
            if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
                throw new KeycloakUserCreationException("El usuario o email ya existe.");
            }
            if (response.getStatus() != 201) {
                String errorDetails = response.readEntity(String.class);
                throw new KeycloakUserCreationException("Error al crear usuario. Estado HTTP: " + response.getStatus() + ". Detalles: " + errorDetails);
            }
            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            log.info("Usuario '{}' creado exitosamente con ID: {}.", request.username(), userId);
            return userId;
        } catch (WebApplicationException e) {
            String errorDetails = e.getResponse().readEntity(String.class);
            log.error("Error al crear usuario: Status={}, Detalles={}", e.getResponse().getStatus(), errorDetails);
            throw new KeycloakUserCreationException("Error de aplicacion al crear usuario: " + errorDetails);
        } catch (Exception e) {
            log.error("Excepcion inesperada al crear usuario: {}", e.getMessage());
            throw new KeycloakUserCreationException("Error inesperado al crear usuario: " + e.getMessage());
        }
    }

    /**
     * Actualiza la informacion de un usuario existente en un realm.
     *
     * @param realm              El nombre del realm de Keycloak.
     * @param userId             El ID del usuario a actualizar.
     * @param updatedUserRequest Los datos de usuario actualizados.
     */
    public void updateUser(String realm, String userId, UserRequest updatedUserRequest) {
        log.info("Actualizando usuario con ID '{}' en el realm '{}'.", userId, realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        try {
            UserResource userResource = utilsAdminService.getRealmResource(keycloakRealm).users().get(userId);
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
            log.error("Fallo la actualizacion del usuario con ID '{}': Status={}", userId, e.getResponse().getStatus());
            throw new KeycloakUserCreationException("Error al actualizar el usuario: " + e.getMessage());
        }
    }

    /**
     * Elimina un usuario por su ID en un realm especifico.
     *
     * @param realm  El nombre del realm de Keycloak.
     * @param userId El ID del usuario a eliminar.
     */
    public void deleteUser(String realm, String userId) {
        log.info("Eliminando usuario con ID '{}' del realm '{}'.", userId, realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        try {
            utilsAdminService.getRealmResource(keycloakRealm).users().get(userId).remove();
            log.info("Usuario con ID '{}' eliminado exitosamente.", userId);
        } catch (NotFoundException e) {
            log.warn("Usuario con ID '{}' no encontrado, no se puede eliminar.", userId);
            throw new NotFoundException("Usuario no encontrado con ID: " + userId);
        } catch (WebApplicationException e) {
            log.error("Fallo al eliminar el usuario con ID '{}': Status={}", userId, e.getResponse().getStatus());
            throw new KeycloakUserCreationException("Error al eliminar el usuario: " + e.getMessage());
        }
    }

    /**
     * Restablece la contrasena de un usuario en un realm especifico.
     *
     * @param realm       El nombre del realm de Keycloak.
     * @param userId      El ID del usuario en Keycloak.
     * @param newPassword La nueva contrasena para el usuario.
     */
    public void resetUserPassword(String realm, String userId, String newPassword) {
        log.info("Iniciando el restablecimiento de contrasena para el usuario con ID '{}' en el realm '{}'.", userId, realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(newPassword);

        try {
            UserResource userResource = utilsAdminService.getRealmResource(keycloakRealm).users().get(userId);
            userResource.resetPassword(passwordCred);
            log.info("Contrasena restablecida exitosamente para el usuario con ID '{}'.", userId);
        } catch (NotFoundException e) {
            log.warn("Usuario con ID '{}' no encontrado, no se puede restablecer la contrasena.", userId);
            throw new NotFoundException("Usuario no encontrado con ID: " + userId);
        } catch (WebApplicationException e) {
            log.error("Fallo la comunicacion con Keycloak al intentar restablecer la contrasena del usuario '{}': Status = {}", userId, e.getResponse().getStatus());
            throw e;
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
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        List<UserRepresentation> users = utilsAdminService.getRealmResource(keycloakRealm).users().searchByEmail(email, true);
        return users != null && !users.isEmpty();
    }

    /**
     * Asigna un rol de cliente a un usuario.
     */
    public void assignClientRoleToUser(String realm, String clientId, String userId, String roleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Asignando el rol de cliente '{}' al usuario '{}' en el cliente '{}' del realm '{}'.", roleName, userId, clientId, keycloakRealm);
        try {
            UserResource userResource = getUserResource(keycloakRealm, userId);
            ClientResource clientResource = getClientResource(keycloakRealm, clientId);
            RoleRepresentation role = clientResource.roles().get(roleName).toRepresentation();
            List<RoleRepresentation> existingClientRoles = userResource.roles().clientLevel(clientResource.toRepresentation().getId()).listAll();
            if (!existingClientRoles.stream().anyMatch(r -> r.getName().equals(roleName))) {
                userResource.roles().clientLevel(clientResource.toRepresentation().getId()).add(List.of(role));
                log.info("Rol de cliente '{}' asignado exitosamente al usuario '{}'.", roleName, userId);
            } else {
                log.warn("El usuario '{}' ya tiene el rol de cliente '{}'. No se realizara ninguna accion.", userId, roleName);
            }
        } catch (NotFoundException e) {
            log.error("Error al asignar rol: usuario, cliente o rol no encontrado. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Elimina un rol de cliente de un usuario.
     */
    public void removeClientRoleFromUser(String realm, String clientId, String userId, String roleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Eliminando el rol de cliente '{}' del usuario '{}' en el cliente '{}' del realm '{}'.", roleName, userId, clientId, keycloakRealm);
        try {
            UserResource userResource = getUserResource(keycloakRealm, userId);
            ClientResource clientResource = getClientResource(keycloakRealm, clientId);
            RoleRepresentation role = clientResource.roles().get(roleName).toRepresentation();
            userResource.roles().clientLevel(clientResource.toRepresentation().getId()).remove(List.of(role));
            log.info("Rol de cliente '{}' eliminado exitosamente del usuario '{}'.", roleName, userId);
        } catch (NotFoundException e) {
            log.error("Error al eliminar rol: usuario, cliente o rol no encontrado. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Elimina todos los roles de cliente de un usuario para un cliente especifico.
     */
    public void removeAllClientRolesFromUser(String realm, String clientId, String userId) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Eliminando todos los roles de cliente del usuario '{}' en el cliente '{}' del realm '{}'.", userId, clientId, keycloakRealm);
        try {
            UserResource userResource = getUserResource(keycloakRealm, userId);
            ClientResource clientResource = getClientResource(keycloakRealm, clientId);
            List<RoleRepresentation> rolesToRemove = userResource.roles().clientLevel(clientResource.toRepresentation().getId()).listAll();
            if (!rolesToRemove.isEmpty()) {
                userResource.roles().clientLevel(clientResource.toRepresentation().getId()).remove(rolesToRemove);
                log.info("Se eliminaron {} roles de cliente del usuario '{}'.", rolesToRemove.size(), userId);
            } else {
                log.info("El usuario '{}' no tiene roles de cliente para el cliente '{}'.", userId, clientId);
            }
        } catch (NotFoundException e) {
            log.error("Error al eliminar roles: usuario o cliente no encontrado. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Actualiza el rol de cliente de un usuario.
     */
    public void updateUserClientRoles(String realm, String clientId, String userId, String newRoleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Actualizando el rol del usuario '{}' al rol de cliente '{}' en el cliente '{}' del realm '{}'.", userId, newRoleName, clientId, keycloakRealm);
        try {
            UserResource userResource = getUserResource(keycloakRealm, userId);
            ClientResource clientResource = getClientResource(keycloakRealm, clientId);
            String clientUuid = clientResource.toRepresentation().getId();
            List<RoleRepresentation> currentClientRoles = userResource.roles().clientLevel(clientUuid).listAll();
            if (!currentClientRoles.isEmpty()) {
                userResource.roles().clientLevel(clientUuid).remove(currentClientRoles);
                log.debug("Roles de cliente existentes eliminados.");
            }
            RoleRepresentation newRole = clientResource.roles().get(newRoleName).toRepresentation();
            userResource.roles().clientLevel(clientUuid).add(List.of(newRole));
            log.info("Rol de cliente '{}' asignado exitosamente al usuario '{}'.", newRoleName, userId);
        } catch (NotFoundException e) {
            log.error("Error al actualizar rol: usuario, cliente o rol no encontrado. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Obtiene todos los usuarios, incluyendo sus roles de cliente para un cliente especifico.
     */
    public List<UserWithRoles> getAllUsersWithClientRoles(String realm, String clientId) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Recuperando todos los usuarios con roles del cliente '{}' en el realm '{}'.", clientId, keycloakRealm);
        try {
            ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
            List<ClientRepresentation> clients = clientsResource.findByClientId(clientId);
            if (clients.isEmpty()) {
                throw new NotFoundException("Cliente '" + clientId + "' no encontrado en el realm '" + keycloakRealm + "'.");
            }
            ClientResource clientResource = clientsResource.get(clients.get(0).getId());
            UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
            List<UserRepresentation> allUsers = usersResource.list();
            return allUsers.stream()
                    .map(userRep -> getUserWithClientRoles(usersResource, clientResource, userRep))
                    .collect(Collectors.toList());
        } catch (NotFoundException e) {
            log.error("Error al obtener usuarios con roles de cliente. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Obtiene un usuario con sus roles de cliente por ID.
     */
    public UserWithRoles getUserByIdWithClientRoles(String realm, String clientId, String userId) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Recuperando usuario '{}' con roles de cliente del cliente '{}' en el realm '{}'.", userId, clientId, keycloakRealm);
        try {
            UserResource userResource = getUserResource(keycloakRealm, userId);
            UserRepresentation userRep = userResource.toRepresentation();
            ClientResource clientResource = getClientResource(keycloakRealm, clientId);
            String clientUuid = clientResource.toRepresentation().getId();
            List<RoleRepresentation> clientRoles = userResource.roles().clientLevel(clientUuid).listAll();
            List<String> roleNames = clientRoles.stream().map(RoleRepresentation::getName).collect(Collectors.toList());
            log.debug("Roles de cliente del usuario '{}': {}", userId, roleNames);
            return new UserWithRoles(
                    userRep.getId(),
                    userRep.getUsername(),
                    userRep.getEmail(),
                    userRep.getFirstName(),
                    userRep.getLastName(),
                    userRep.isEnabled(),
                    userRep.isEmailVerified(),
                    roleNames
            );
        } catch (NotFoundException e) {
            log.error("Error al obtener el usuario con roles de cliente: usuario o cliente no encontrado. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Obtiene un usuario con sus roles de cliente por email.
     */
    public UserWithRoles getUserByEmailWithClientRoles(String realm, String clientId, String email) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Recuperando usuario por email '{}' con roles de cliente del cliente '{}' en el realm '{}'.", email, clientId, keycloakRealm);
        try {
            UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
            List<UserRepresentation> users = usersResource.searchByEmail(email, true);
            if (users.isEmpty()) {
                throw new NotFoundException("User not found with email: " + email);
            }
            UserRepresentation userRep = users.get(0);
            return getUserByIdWithClientRoles(realm, clientId, userRep.getId());
        } catch (NotFoundException e) {
            log.error("Error al obtener el usuario con roles de cliente por email. Detalles: {}", e.getMessage());
            throw e;
        }
    }

    private UserWithRoles getUserWithClientRoles(UsersResource usersResource, ClientResource clientResource, UserRepresentation userRep) {
        UserResource userResource = usersResource.get(userRep.getId());
        List<RoleRepresentation> clientRoles = userResource.roles().clientLevel(clientResource.toRepresentation().getId()).listAll();
        List<String> roleNames = clientRoles.stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
        return new UserWithRoles(
                userRep.getId(),
                userRep.getUsername(),
                userRep.getEmail(),
                userRep.getFirstName(),
                userRep.getLastName(),
                userRep.isEnabled(),
                userRep.isEmailVerified(),
                roleNames
        );
    }

    private UserResource getUserResource(String realm, String userId) {
        try {
            return utilsAdminService.getRealmResource(realm).users().get(userId);
        } catch (NotFoundException e) {
            throw new NotFoundException("Usuario '" + userId + "' no encontrado.");
        }
    }

    private ClientResource getClientResource(String realm, String clientId) {
        ClientsResource clientsResource = utilsAdminService.getRealmResource(realm).clients();
        List<ClientRepresentation> clients = clientsResource.findByClientId(clientId);
        if (clients.isEmpty()) {
            throw new NotFoundException("Cliente '" + clientId + "' no encontrado.");
        }
        return clientsResource.get(clients.get(0).getId());
    }
}