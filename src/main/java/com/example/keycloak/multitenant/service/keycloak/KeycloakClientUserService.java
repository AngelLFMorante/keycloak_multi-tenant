package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserWithDetailedClientRoles;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
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
    public List<UserWithDetailedClientRoles> getAllUsersWithRoles(String realm) {
        log.info("Recuperando todos los usuarios con roles del realm '{}'.", realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        UsersResource usersResource;
        ClientsResource clientsResource;
        try {
            usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
            clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        } catch (WebApplicationException e) {
            log.error("Error al obtener el recurso de usuarios para el realm '{}': Status={}", keycloakRealm, e.getResponse().getStatus(), e);
            throw e;
        }

        List<UserRepresentation> userRepresentations = usersResource.list();
        log.debug("Se encontraron {} representaciones de usuario en el realm '{}'.", userRepresentations.size(), keycloakRealm);

        List<ClientRepresentation> allClients = clientsResource.findAll();

        return userRepresentations.stream()
                .map(userRep -> {
                    List<Map<String, List<String>>> allClientRoleNames = allClients.stream()
                            .map(client -> {
                                try {
                                    String clientUuid = client.getId();
                                    List<RoleRepresentation> clientRoles = usersResource.get(userRep.getId()).roles().clientLevel(clientUuid).listAll();
                                    if (!clientRoles.isEmpty()) {
                                        List<String> roleNames = clientRoles.stream().map(RoleRepresentation::getName).toList();
                                        return Map.of(client.getClientId(), roleNames);
                                    }
                                } catch (WebApplicationException e) {
                                    log.error("Error al obtener roles para el usuario '{}': Status={}", userRep.getId(), e.getResponse().getStatus(), e);
                                }
                                return null;
                            })
                            .filter(Objects::nonNull)
                            .toList();

                    return new UserWithDetailedClientRoles(
                            userRep.getId(),
                            userRep.getUsername(),
                            userRep.getEmail(),
                            userRep.getFirstName(),
                            userRep.getLastName(),
                            userRep.isEnabled(),
                            userRep.isEmailVerified(),
                            allClientRoleNames
                    );
                })
                .toList();
    }

    /**
     * Obtiene un usuario con sus roles de cliente por ID.
     */
    public UserWithDetailedClientRoles getUserByIdWithClientRoles(String realm, String userId) {
        log.info("Recuperando usuario con ID '{}' del realm de Keycloak '{}'.", userId, realm);

        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        UsersResource usersResource = utilsAdminService.getRealmResource(keycloakRealm).users();
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();

        UserRepresentation user;
        try {
            user = usersResource.get(userId).toRepresentation();
            List<ClientRepresentation> allClients = clientsResource.findAll();

            List<Map<String, List<String>>> allClientRoleNames = allClients.stream()
                    .map(client -> {
                        try {
                            String clientUuid = client.getId();
                            List<RoleRepresentation> clientRoles = usersResource.get(user.getId()).roles().clientLevel(clientUuid).listAll();
                            if (!clientRoles.isEmpty()) {
                                List<String> roleNames = clientRoles.stream().map(RoleRepresentation::getName).toList();
                                return Map.of(client.getClientId(), roleNames);
                            }
                        } catch (WebApplicationException e) {
                            log.error("Error al obtener roles para el usuario '{}': Status={}", user.getId(), e.getResponse().getStatus(), e);
                        }
                        return null;
                    })
                    .filter(Objects::nonNull)
                    .toList();
            log.debug("Usuario '{}' encontrado con roles: {}", user.getUsername(), allClientRoleNames);

            log.debug("Roles de cliente del usuario '{}': {}", userId, allClientRoleNames);
            return new UserWithDetailedClientRoles(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    user.getFirstName(),
                    user.getLastName(),
                    user.isEnabled(),
                    user.isEmailVerified(),
                    allClientRoleNames
            );
        } catch (NotFoundException e) {
            log.error("Usuario con ID '{}' no encontrado en el realm '{}'.", userId, keycloakRealm, e);
            throw e;
        }
    }

}
