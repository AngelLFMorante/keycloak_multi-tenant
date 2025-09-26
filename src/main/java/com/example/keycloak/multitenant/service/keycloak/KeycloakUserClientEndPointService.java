package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithDetailedClientRoles;
import com.example.keycloak.multitenant.model.user.UserWithDetailedRolesAndAttributes;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de bajo nivel para la gestion de usuarios, roles de cliente, y
 * la interaccion con la API de administracion de Keycloak.
 * <p>
 * !Servicio para obtener solo un cliente de roles por usuario
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakUserClientEndPointService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUserClientEndPointService.class);
    private final KeycloakAdminService utilsAdminService;
    private final KeycloakConfigService utilsConfigService;

    public KeycloakUserClientEndPointService(KeycloakAdminService utilsAdminService, KeycloakConfigService utilsConfigService) {
        this.utilsAdminService = utilsAdminService;
        this.utilsConfigService = utilsConfigService;
        log.info("KeycloakClientUserService inicializado.");
    }

    /**
     * Recupera todos los usuarios de un realm de Keycloak, incluyendo sus roles.
     * <p>
     * Este método obtiene la lista completa de usuarios y, para cada uno, realiza una
     * llamada adicional para obtener y mapear sus roles de nivel de realm.
     *
     * @param realm El nombre interno del realm de Keycloak.
     * @return Una lista de {@link UserWithDetailedClientRoles} que contiene los detalles de cada usuario
     * y sus roles.
     * @throws WebApplicationException Si ocurre un error al comunicarse con la API de Keycloak.
     */
    public List<UserWithRoles> getAllUsersWithRoles(String realm, String clientId) {
        log.info("Recuperando todos los usuarios con roles del client {} del realm '{}'.", clientId, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        UsersResource usersResource;
        ClientsResource clientsResource;
        List<ClientRepresentation> clients;
        try {
            usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
            clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
            clients = clientsResource.findByClientId(clientId);
        } catch (WebApplicationException e) {
            log.error("Error al obtener el recurso de usuarios para el realm '{}': Status={}", keycloakRealm, e.getResponse().getStatus(), e);
            throw e;
        }
        ClientResource clientResource = clientsResource.get(clients.get(0).getId());
        String clientUUID = clientResource.toRepresentation().getId();
        List<UserRepresentation> userRepresentations = usersResource.list();
        log.debug("Se encontraron {} representaciones de usuario en el realm '{}'.", userRepresentations.size(), keycloakRealm);

        return userRepresentations.stream()
                .map(userRep -> {

                    List<RoleRepresentation> realmRoles;
                    try {
                        realmRoles = usersResource.get(userRep.getId()).roles().clientLevel(clientUUID).listAll();
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
    public UserWithRoles getUserByIdWithClientRoles(String realm, String clientId, String userId) {
        log.info("Recuperando usuario con ID '{}' con roles del cliente {} del realm de Keycloak '{}'.", userId, clientId, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        List<ClientRepresentation> clients;
        try {
            UserRepresentation user = usersResource.get(userId).toRepresentation();
            clients = clientsResource.findByClientId(clientId);
            ClientResource clientResource = clientsResource.get(clients.get(0).getId());
            String clientUUID = clientResource.toRepresentation().getId();

            List<RoleRepresentation> realmRoles;
            try {
                realmRoles = usersResource.get(user.getId()).roles().clientLevel(clientUUID).listAll();
            } catch (WebApplicationException e) {
                log.error("Error al obtener roles para el usuario '{}': Status={}", user.getId(), e.getResponse().getStatus(), e);
                realmRoles = Collections.emptyList();
            }
            List<String> roleNames = realmRoles.stream()
                    .map(RoleRepresentation::getName).toList();
            log.debug("Roles de cliente del usuario '{}': {}", userId, roleNames);

            return new UserWithRoles(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    user.getFirstName(),
                    user.getLastName(),
                    user.isEnabled(),
                    user.isEmailVerified(),
                    roleNames
            );
        } catch (NotFoundException e) {
            log.error("Usuario con ID '{}' no encontrado en el realm '{}'.", userId, keycloakRealm, e);
            throw e;
        }
    }

    /**
     * Recupera un usuario por su email junto con sus roles a nivel de realm en Keycloak.
     * <p>
     * Este método busca un usuario por su dirección de email. Si encuentra el usuario,
     * también recupera y mapea sus roles para construir un objeto UserWithDetailedClientRoles.
     *
     * @param realm El nombre interno del realm de Keycloak.
     * @param email El correo electrónico del usuario.
     * @return Un DTO {@link UserWithRoles} con los datos del usuario y una lista de sus roles.
     * @throws NotFoundException Si no se encuentra ningún usuario con el email proporcionado.
     */
    public UserWithRoles getUserByEmailWithRoles(String realm, String clientId, String email) {
        log.info("Recuperando usuario por email '{}' del realm keycloak '{}'.", email, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Realm '{}' mapeado al realm de keycloak: '{}'", realm, keycloakRealm);

        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        List<UserRepresentation> users = usersResource.searchByEmail(email, true);

        if (users == null || users.isEmpty()) {
            log.error("Usuario con email '{}' no encontrado en el realm '{}'.", email, keycloakRealm);
            throw new NotFoundException("User not found with email: " + email);
        }

        UserRepresentation user = users.get(0);
        List<ClientRepresentation> allClients = clientsResource.findByClientId(clientId);
        List<String> clientRoleNames = getClientRolesForUser(user.getId(), usersResource, allClients.get(0).getId());
        log.debug("Usuario '{}' encontrado con roles: {}", user.getUsername(), clientRoleNames);

        return new UserWithRoles(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.isEnabled(),
                user.isEmailVerified(),
                clientRoleNames
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
    public List<UserWithRolesAndAttributes> getUsersByAttributes(String realm, String clientId, UserSearchCriteria criteria) {
        log.info("Buscando usuarios en el realm '{}' por los atributos: {}", realm, criteria);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado a Keycloak realm '{}'.", realm, keycloakRealm);
        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();

        List<UserRepresentation> allUsers = usersResource.list();
        List<ClientRepresentation> allClients = clientsResource.findByClientId(clientId);
        log.debug("Total de usuarios encontrados en el realm '{}': {}", keycloakRealm, allUsers);

        return allUsers.stream()
                .filter(user -> matchesCriteria(user, criteria))
                .map(userRep -> createUserDto(userRep, usersResource, allClients))
                .toList();
    }

    /**
     * Mapea un UserRepresentation de Keycloak a un DTO de la aplicación.
     * Este método privado mejora la legibilidad y separa la lógica de conversión.
     *
     * @param userRep       La representación del usuario de Keycloak.
     * @param usersResource El recurso de usuarios para obtener los roles.
     * @param allClients    todos los clientes del realm
     * @return Un DTO UserWithRolesAndAttributes completo.
     */
    private UserWithRolesAndAttributes createUserDto(UserRepresentation userRep, UsersResource usersResource, List<ClientRepresentation> allClients) {
        log.debug("Iniciando la creacion del DTO para el usuario con ID: {}", userRep.getId());
        List<String> clientRoleNames = getUserRoles(userRep.getId(), usersResource, allClients);
        log.debug("Usuario '{}' encontrado con roles: {}", userRep.getUsername(), clientRoleNames);

        UserWithRoles userWithRoles = new UserWithRoles(
                userRep.getId(),
                userRep.getUsername(),
                userRep.getEmail(),
                userRep.getFirstName(),
                userRep.getLastName(),
                userRep.isEnabled(),
                userRep.isEmailVerified(),
                clientRoleNames
        );

        Map<String, List<String>> userAttributes = userRep.getAttributes() != null ? userRep.getAttributes() : Collections.emptyMap();
        log.debug("DTO creado para el usuario '{}'", userRep.getUsername());
        return new UserWithRolesAndAttributes(userWithRoles, userAttributes);
    }

    /**
     * **Método reutilizable para obtener los roles de cliente de un usuario.**
     * Este método elimina la duplicación de código.
     *
     * @param userId        El ID del usuario.
     * @param usersResource El recurso de usuarios de Keycloak.
     * @param clientUUID    ID cliente del realm (obtenida una sola vez).
     * @return Una lista de mapas de clientes y sus roles.
     */
    private List<String> getClientRolesForUser(String userId, UsersResource usersResource, String clientUUID) {
        log.debug("Obteniendo roles para el usuario con ID: {}", userId);

        try {
            List<RoleRepresentation> clientRoles = usersResource.get(userId).roles().clientLevel(clientUUID).listAll();
            if (!clientRoles.isEmpty()) {
                return clientRoles.stream().map(RoleRepresentation::getName).toList();
            }
        } catch (WebApplicationException e) {
            log.error("Error al obtener roles de cliente para el usuario '{}': Status={}", userId, e.getResponse().getStatus(), e);
        }
        return null;
    }

    /**
     * Obtiene los nombres de los roles de un usuario específico.
     * Maneja excepciones si la comunicación con Keycloak falla.
     *
     * @param userId        El ID del usuario.
     * @param usersResource El recurso de usuarios de Keycloak.
     * @param allClients
     * @return Una lista de nombres de roles o una lista vacía si hay un error.
     */
    private List<String> getUserRoles(String userId, UsersResource usersResource, List<ClientRepresentation> allClients) {
        log.debug("Obteniendo roles para el usuario con ID: {}", userId);
        try {
            try {
                String clientUuid = allClients.get(0).getId();
                List<RoleRepresentation> clientRoles = usersResource.get(userId).roles().clientLevel(clientUuid).listAll();
                if (!clientRoles.isEmpty()) {
                    return clientRoles.stream().map(RoleRepresentation::getName).toList();
                }
            } catch (WebApplicationException e) {
                log.error("Error al obtener roles para el usuario '{}': Status={}", userId, e.getResponse().getStatus(), e);
            }
            return null;
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
