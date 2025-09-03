package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
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
    private final KeycloakConfigService utilsConfigService;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param keycloakRoleService Servicio para operaciones relacionadas con roles.
     * @param utilsAdminService   Servicio de utilidades para obtener recursos de Keycloak.
     * @param utilsConfigService  Servicio de utilidades para interactuar con Keycloak.
     */
    public KeycloakUserService(KeycloakRoleService keycloakRoleService, KeycloakAdminService utilsAdminService, KeycloakConfigService utilsConfigService) {
        this.keycloakRoleService = keycloakRoleService;
        this.utilsAdminService = utilsAdminService;
        this.utilsConfigService = utilsConfigService;
        log.info("KeycloakUserService inicializado.");
    }

    /**
     * Recupera todos los usuarios de un realm de Keycloak, incluyendo sus roles.
     * <p>
     * Este método obtiene la lista completa de usuarios y, para cada uno, realiza una
     * llamada adicional para obtener y mapear sus roles de nivel de realm.
     *
     * @param realm El nombre interno del realm de Keycloak.
     * @return Una lista de {@link UserWithRoles} que contiene los detalles de cada usuario
     * y sus roles.
     * @throws WebApplicationException Si ocurre un error al comunicarse con la API de Keycloak.
     */
    public List<UserWithRoles> getAllUsersWithRoles(String realm) {
        log.info("Recuperando todos los usuarios con roles del realm '{}'.", realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        UsersResource usersResource;
        try {
            usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        } catch (WebApplicationException e) {
            log.error("Error al obtener el recurso de usuarios para el realm '{}': Status={}", keycloakRealm, e.getResponse().getStatus(), e);
            throw e;
        }

        List<UserRepresentation> userRepresentations = usersResource.list();
        log.debug("Se encontraron {} representaciones de usuario en el realm '{}'.", userRepresentations.size(), keycloakRealm);

        return userRepresentations.stream()
                .map(userRep -> {

                    List<RoleRepresentation> realmRoles;
                    try {
                        realmRoles = usersResource.get(userRep.getId()).roles().realmLevel().listAll();
                    } catch (WebApplicationException e) {
                        log.error("Error al obtener roles para el usuario '{}': Status={}", userRep.getId(), e.getResponse().getStatus(), e);
                        realmRoles = Collections.emptyList();
                    }
                    List<String> roleNames = realmRoles.stream()
                            .map(RoleRepresentation::getName).toList();

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
                })
                .toList();
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
    public void createUserWithRole(String realm, UserRequest request, String tempPassword) {
        log.info("Iniciando el proceso de registro para el usuario '{}' en el realm '{}'.", request.username(), realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);

        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

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

        String keycloakRealm = utilsConfigService.resolveRealm(realm);

        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

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

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        try {
            RealmResource realmResource = utilsAdminService.getRealmResource(keycloakRealm);
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
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        try {
            utilsAdminService.getRealmResource(keycloakRealm).users().get(userId).remove();
            log.info("Usuario con ID '{}' eliminado exitosamente.", userId);
        } catch (NotFoundException e) {
            log.warn("Usuario con ID '{}' no encontrado, no se puede eliminar.", userId);
            throw new NotFoundException("Usuario no encontrado con ID: " + userId);
        } catch (WebApplicationException e) {
            log.error("Fallo al eliminar el usuario con ID '{}': Status={}", userId, e.getResponse().getStatus(), e);
            throw new KeycloakUserCreationException("Error al eliminar el usuario: " + e.getMessage(), e);
        }
    }

    /**
     * Recupera un usuario por su ID junto con sus roles a nivel de realm en Keycloak.
     * <p>
     * Este método interactúa directamente con la API de administración de Keycloak para
     * obtener la representación del usuario y luego una lista de sus roles. Si el
     * usuario no tiene roles, la lista estará vacía, y solo se lanzará una excepción
     * si el usuario no es encontrado.
     *
     * @param realm  El nombre interno del realm de Keycloak.
     * @param userId El ID único del usuario en Keycloak.
     * @return Un DTO {@link UserWithRoles} con los datos del usuario y una lista
     * de sus roles.
     * @throws NotFoundException Si el usuario no es encontrado en el realm especificado.
     */
    public UserWithRoles getUserByIdWithRoles(String realm, String userId) {
        log.info("Recuperando usuario con ID '{}' del realm de Keycloak '{}'.", userId, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        RealmResource realmResource = utilsAdminService.getRealmResource(keycloakRealm);
        UsersResource usersResource = realmResource.users();

        UserRepresentation user;
        try {
            user = usersResource.get(userId).toRepresentation();
        } catch (NotFoundException e) {
            log.error("Usuario con ID '{}' no encontrado en el realm '{}'.", userId, keycloakRealm, e);
            throw e;
        }

        List<RoleRepresentation> roleReps = usersResource.get(userId).roles().realmLevel().listAll();
        List<String> roles = roleReps.stream()
                .map(RoleRepresentation::getName).toList();

        log.debug("Usuario '{}' encontrado con roles: {}", user.getUsername(), roles);

        return new UserWithRoles(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isEnabled(),
                user.isEmailVerified(),
                roles
        );
    }

    /**
     * Recupera un usuario por su email junto con sus roles a nivel de realm en Keycloak.
     * <p>
     * Este método busca un usuario por su dirección de email. Si encuentra el usuario,
     * también recupera y mapea sus roles para construir un objeto UserWithRoles.
     *
     * @param realm El nombre interno del realm de Keycloak.
     * @param email El correo electrónico del usuario.
     * @return Un DTO {@link UserWithRoles} con los datos del usuario y una lista de sus roles.
     * @throws NotFoundException Si no se encuentra ningún usuario con el email proporcionado.
     */
    public UserWithRoles getUserByEmailWithRoles(String realm, String email) {
        log.info("Recuperando usuario por email '{}' del realm keycloak '{}'.", email, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Realm '{}' mapeado al realm de keycloak: '{}'", realm, keycloakRealm);

        UsersResource userResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        List<UserRepresentation> users = userResource.searchByEmail(email, true);

        if (users == null || users.isEmpty()) {
            log.error("Usuario con email '{}' no encontrado en el realm '{}'.", email, keycloakRealm);
            throw new NotFoundException("User not found with email: " + email);
        }

        UserRepresentation user = users.get(0);
        List<RoleRepresentation> roleReps = userResource.get(user.getId()).roles().realmLevel().listAll();
        List<String> roles = roleReps.stream().map(RoleRepresentation::getName).toList();

        log.debug("Usuario '{}' encontrado con roles: {}", user.getUsername(), roles);

        return new UserWithRoles(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isEnabled(),
                user.isEmailVerified(),
                roles
        );
    }

    /**
     * Recupera una lista de usuarios de Keycloak filtrados por atributos personalizados.
     * Es la forma más eficiente dado que la API de Keycloak no soporta búsqueda directa por atributos.
     *
     * @param realm    El nombre del realm de Keycloak.
     * @param criteria Un DTO con los criterios de búsqueda (organization, subsidiary, department).
     * @return Una lista de {@link UserWithRolesAndAttributes} que cumplen con los criterios.
     * @throws WebApplicationException Si la comunicación con Keycloak falla.
     */
    public List<UserWithRolesAndAttributes> getUsersByAttributes(String realm, UserSearchCriteria criteria) {
        log.info("Buscando usuarios en el realm '{}' por los atributos: {}", realm, criteria);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado a Keycloak realm '{}'.", realm, keycloakRealm);

        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        List<UserRepresentation> allUsers = usersResource.list();
        log.debug("Total de usuarios encontrados en el realm '{}': {}", keycloakRealm, allUsers);

        return allUsers.stream()
                .filter(user -> matchesCriteria(user, criteria))
                .map(userRep -> createUserDto(userRep, usersResource))
                .toList();
    }

    /**
     * Restablece la contrasena de un usuario en un realm especifico de Keycloak.
     * <p>
     * Utiliza la API de administracion para establecer una nueva contrasena. La nueva
     * contrasena no sera temporal, lo que significa que el usuario no tendra que
     * cambiarla en su proximo inicio de sesion.
     *
     * @param realm       El nombre del realm de Keycloak.
     * @param userId      El ID del usuario en Keycloak.
     * @param newPassword La nueva contrasena para el usuario.
     * @throws NotFoundException       Si el usuario no se encuentra en el realm.
     * @throws WebApplicationException Si la comunicacion con Keycloak falla.
     */
    public void resetUserPassword(String realm, String userId, String newPassword) {
        log.info("Iniciando el restablecimiento de contrasena para el usuario con ID '{}' en el realm '{}'.", userId, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado a Keycloak realm '{}'.", realm, keycloakRealm);

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
            log.error("Fallo la comunicacion con Keycloak al intentar restablecer la contrasena del usuario '{}': Status = {}", userId, e.getResponse().getStatus(), e);
            throw e;
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

    /**
     * Mapea un UserRepresentation de Keycloak a un DTO de la aplicación.
     * Este método privado mejora la legibilidad y separa la lógica de conversión.
     *
     * @param userRep       La representación del usuario de Keycloak.
     * @param usersResource El recurso de usuarios para obtener los roles.
     * @return Un DTO UserWithRolesAndAttributes completo.
     */
    private UserWithRolesAndAttributes createUserDto(UserRepresentation userRep, UsersResource usersResource) {
        log.debug("Iniciando la creacion del DTO para el usuario con ID: {}", userRep.getId());
        List<String> rolesNames = getUserRoles(userRep.getId(), usersResource);

        UserWithRoles userWithRoles = new UserWithRoles(
                userRep.getId(),
                userRep.getUsername(),
                userRep.getEmail(),
                userRep.getFirstName(),
                userRep.getLastName(),
                userRep.isEnabled(),
                userRep.isEmailVerified(),
                rolesNames
        );

        Map<String, List<String>> userAttributes = userRep.getAttributes() != null ? userRep.getAttributes() : Collections.emptyMap();

        log.debug("DTO creado para el usuario '{}'", userRep.getUsername());

        return new UserWithRolesAndAttributes(userWithRoles, userAttributes);
    }

    /**
     * Obtiene los nombres de los roles de un usuario específico.
     * Maneja excepciones si la comunicación con Keycloak falla.
     *
     * @param userId        El ID del usuario.
     * @param usersResource El recurso de usuarios de Keycloak.
     * @return Una lista de nombres de roles o una lista vacía si hay un error.
     */
    private List<String> getUserRoles(String userId, UsersResource usersResource) {
        log.debug("Obteniendo roles para el usuario con ID: {}", userId);
        try {
            List<RoleRepresentation> realmRoles = usersResource.get(userId).roles().realmLevel().listAll();
            log.debug("Roles obtenidos para el usuario '{}': {}", userId, realmRoles.size());
            return realmRoles.stream().map(RoleRepresentation::getName).toList();
        } catch (WebApplicationException e) {
            log.error("Error al obtener roles para el usuario '{}': Status = {}", userId, e.getResponse().getStatus(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Método auxiliar para filtrar usuarios por sus atributos.
     *
     * @param userRepresentation La representación del usuario a evaluar.
     * @param criteria           Los criterios de búsqueda.
     * @return {@code true} si el usuario cumple con todos los criterios, {@code false} en caso contrario.
     */
    private boolean matchesCriteria(UserRepresentation userRepresentation, UserSearchCriteria criteria) {
        if (criteria.organization() == null && criteria.subsidiary() == null && criteria.department() == null) {
            log.debug("No se proporcionaron criterios de busqueda, el usuario '{}' coincide por defecto.", userRepresentation.getUsername());
            return true;
        }

        if (userRepresentation.getAttributes() == null) {
            log.debug("El usuario '{}' no tiene atributos, por lo tanto, no coincide.", userRepresentation.getUsername());
            return false;
        }

        Map<String, List<String>> attributes = userRepresentation.getAttributes();

        if (criteria.organization() != null && !criteria.organization().isBlank()) {
            List<String> orgAttrs = attributes.getOrDefault("organization", Collections.emptyList());
            if (!orgAttrs.contains(criteria.organization())) {
                log.debug("El usuario '{}' no coincide con el criterio de organizacion '{}'.", userRepresentation.getUsername(), criteria.organization());
                return false;
            }
        }

        if (criteria.subsidiary() != null && !criteria.subsidiary().isBlank()) {
            List<String> subAttrs = attributes.getOrDefault("subsidiary", Collections.emptyList());
            if (!subAttrs.contains(criteria.subsidiary())) {
                log.debug("El usuario '{}' no coincide con el criterio de filial '{}'.", userRepresentation.getUsername(), criteria.subsidiary());
                return false;
            }
        }

        if (criteria.department() != null && !criteria.department().isBlank()) {
            List<String> depAttrs = attributes.getOrDefault("department", Collections.emptyList());
            if (!depAttrs.contains(criteria.department())) {
                log.debug("El usuario '{}' no coincide con el criterio de departamento '{}'.", userRepresentation.getUsername(), criteria.department());
                return false;
            }
        }

        log.debug("El usuario '{}' coincide con todos los criterios de busqueda.", userRepresentation.getUsername());
        return true;
    }
}
