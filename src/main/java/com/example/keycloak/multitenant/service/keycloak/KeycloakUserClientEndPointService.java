package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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
     * Recupera todos los usuarios de un realm de Keycloak, incluyendo sus roles para un cliente específico.
     */
    public List<UserWithRoles> getAllUsersWithRoles(String realm, String clientId) {
        log.info("Recuperando todos los usuarios con roles del cliente {} del realm '{}'.", clientId, realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        String clientUUID = resolveClientUuid(clientsResource, clientId);
        List<UserRepresentation> userRepresentations = usersResource.list();

        return userRepresentations.stream()
                .map(userRep -> new UserWithRoles(
                        userRep.getId(),
                        userRep.getUsername(),
                        userRep.getEmail(),
                        userRep.getFirstName(),
                        userRep.getLastName(),
                        userRep.isEnabled(),
                        userRep.isEmailVerified(),
                        getClientRolesForUser(usersResource, userRep.getId(), clientUUID)
                ))
                .toList();
    }

    /**
     * Recupera un usuario por su ID junto con sus roles a nivel de cliente.
     */
    public UserWithRoles getUserByIdWithClientRoles(String realm, String clientId, String userId) {
        log.info("Recuperando usuario con ID '{}' con roles del cliente {} del realm de Keycloak '{}'.", userId, clientId, realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        String clientUUID = resolveClientUuid(clientsResource, clientId);

        try {
            UserRepresentation user = usersResource.get(userId).toRepresentation();
            List<String> roleNames = getClientRolesForUser(usersResource, user.getId(), clientUUID);
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
     * Recupera un usuario por su email junto con sus roles a nivel de cliente.
     */
    public UserWithRoles getUserByEmailWithRoles(String realm, String clientId, String email) {
        log.info("Recuperando usuario por email '{}' del realm keycloak '{}'.", email, realm);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        String clientUUID = resolveClientUuid(clientsResource, clientId);
        List<UserRepresentation> users = usersResource.searchByEmail(email, true);

        if (users == null || users.isEmpty()) {
            log.error("Usuario con email '{}' no encontrado en el realm '{}'.", email, keycloakRealm);
            throw new NotFoundException("User not found with email: " + email);
        }

        UserRepresentation user = users.get(0);
        List<String> clientRoleNames = getClientRolesForUser(usersResource, user.getId(), clientUUID);
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
     * Recupera una lista de usuarios de Keycloak filtrados por atributos personalizados, incluyendo roles de un cliente específico.
     */
    public List<UserWithRolesAndAttributes> getUsersByAttributes(String realm, String clientId, UserSearchCriteria criteria) {
        log.info("Buscando usuarios en el realm '{}' por los atributos: {}", realm, criteria);
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        String clientUUID = resolveClientUuid(clientsResource, clientId);
        List<UserRepresentation> allUsers = usersResource.list();

        return allUsers.stream()
                .filter(user -> matchesCriteria(user, criteria))
                .map(userRep -> createUserDto(userRep, usersResource, clientUUID))
                .toList();
    }

    /**
     * Resuelve el Client UUID a partir del Client ID, manejando el caso de cliente no encontrado.
     */
    private String resolveClientUuid(ClientsResource clientsResource, String clientId) {
        List<ClientRepresentation> clients = clientsResource.findByClientId(clientId);
        if (clients == null || clients.isEmpty()) {
            throw new NotFoundException("Client not found with ID: " + clientId);
        }
        return clients.get(0).getId();
    }

    /**
     * Mapea un UserRepresentation de Keycloak a un DTO de la aplicación.
     */
    private UserWithRolesAndAttributes createUserDto(UserRepresentation userRep, UsersResource usersResource, String clientUUID) {
        log.debug("Iniciando la creacion del DTO para el usuario con ID: {}", userRep.getId());
        List<String> clientRoleNames = getClientRolesForUser(usersResource, userRep.getId(), clientUUID);
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
        return new UserWithRolesAndAttributes(userWithRoles, userAttributes);
    }

    /**
     * Método reutilizable para obtener los roles de cliente de un usuario.
     */
    private List<String> getClientRolesForUser(UsersResource usersResource, String userId, String clientUUID) {
        log.debug("Obteniendo roles para el usuario con ID: {}", userId);
        try {
            List<RoleRepresentation> clientRoles = usersResource.get(userId).roles().clientLevel(clientUUID).listAll();
            return clientRoles.stream().map(RoleRepresentation::getName).toList();
        } catch (WebApplicationException e) {
            log.error("Error al obtener roles de cliente para el usuario '{}': Status={}", userId, e.getResponse().getStatus(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Método auxiliar para filtrar usuarios por sus atributos.
     */
    private boolean matchesCriteria(UserRepresentation userRepresentation, UserSearchCriteria criteria) {
        // ... (Tu lógica de filtro de atributos)
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