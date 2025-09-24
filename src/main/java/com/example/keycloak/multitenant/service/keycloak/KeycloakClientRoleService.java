package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para la gestión de roles a nivel de cliente en Keycloak.
 * <p>
 * Este servicio encapsula las operaciones de bajo nivel para interactuar
 * con la API de Keycloak, específicamente para roles asociados a un cliente.
 */
@Service
public class KeycloakClientRoleService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakClientRoleService.class);
    private final KeycloakAdminService utilsAdminService;
    private final KeycloakConfigService utilsConfigService;

    public KeycloakClientRoleService(KeycloakAdminService utilsAdminService, KeycloakConfigService utilsConfigService) {
        this.utilsAdminService = utilsAdminService;
        this.utilsConfigService = utilsConfigService;
        log.info("KeycloakClientRoleService inicializado.");
    }

    // --- Métodos de Roles de Cliente ---

    public List<RoleRepresentation> getClientRoles(String realm, String client) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Buscando todos los roles del cliente '{}' en el realm '{}'.", client, keycloakRealm);
        try {
            ClientResource clientResource = getClientResource(keycloakRealm, client);
            List<RoleRepresentation> roles = clientResource.roles().list();
            log.info("Se encontraron {} roles para el cliente '{}'.", roles.size(), client);
            return roles;
        } catch (NotFoundException e) {
            log.error("Cliente '{}' no encontrado en el realm '{}'.", client, keycloakRealm, e);
            throw new NotFoundException("Cliente '" + client + "' no encontrado.");
        } catch (Exception e) {
            log.error("Excepción inesperada al obtener roles del cliente '{}': {}", client, e.getMessage(), e);
            throw new RuntimeException("Error inesperado al obtener roles del cliente: " + e.getMessage(), e);
        }
    }

    public void createClientRole(String realm, String client, CreateRoleRequest request) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando crear el rol de cliente '{}' para el cliente '{}' en el realm '{}'.", request.name(), client, keycloakRealm);
        try {
            ClientResource clientResource = getClientResource(keycloakRealm, client);
            RoleRepresentation role = new RoleRepresentation();
            role.setName(request.name());
            role.setDescription(request.description());
            role.setClientRole(true);

            clientResource.roles().create(role);
            log.info("Rol de cliente '{}' creado exitosamente.", request.name());
        } catch (WebApplicationException e) {
            String errorMessage = "Error al crear el rol de cliente '" + request.name() + "'. Estado HTTP: " + e.getResponse().getStatus();
            log.error("Error al crear el rol de cliente '{}': {}", request.name(), e.getMessage());
            throw new KeycloakRoleCreationException(errorMessage);
        } catch (Exception e) {
            log.error("Excepción inesperada al crear el rol de cliente '{}': {}", request.name(), e.getMessage(), e);
            throw new RuntimeException("Error inesperado al crear el rol de cliente: " + e.getMessage(), e);
        }
    }

    public void deleteClientRole(String realm, String client, String roleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando eliminar el rol de cliente '{}' del cliente '{}' en el realm '{}'.", roleName, client, keycloakRealm);
        try {
            ClientResource clientResource = getClientResource(keycloakRealm, client);
            clientResource.roles().deleteRole(roleName);
            log.info("Rol de cliente '{}' eliminado exitosamente.", roleName);
        } catch (NotFoundException e) {
            log.error("Rol de cliente '{}' no encontrado en el cliente '{}'.", roleName, client);
            throw new NotFoundException("Rol de cliente '" + roleName + "' no encontrado en el cliente '" + client + "'.");
        } catch (Exception e) {
            log.error("Excepción inesperada al eliminar el rol de cliente '{}': {}", roleName, e.getMessage(), e);
            throw new RuntimeException("Error inesperado al eliminar el rol de cliente: " + e.getMessage(), e);
        }
    }

    public Map<String, List<String>> getClientRoleAttributes(String realm, String client, String roleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Obteniendo atributos del rol de cliente '{}' en el cliente '{}' del realm '{}'.", roleName, client, keycloakRealm);
        RoleRepresentation role = getClientRoleRepresentation(keycloakRealm, client, roleName);
        if (role.getAttributes() == null || role.getAttributes().isEmpty()) {
            log.warn("El rol de cliente '{}' no tiene atributos en el cliente '{}'.", roleName, client);
            return Map.of();
        }
        return role.getAttributes();
    }

    public void addOrUpdateClientRoleAttributes(String realm, String client, String roleName, Map<String, List<String>> roleAttributes) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Actualizando atributos para el rol de cliente '{}' en el cliente '{}' del realm '{}'.", roleName, client, keycloakRealm);
        if (roleAttributes == null || roleAttributes.isEmpty()) {
            throw new IllegalArgumentException("El mapa de atributos no puede estar vacío.");
        }
        RoleRepresentation role = getClientRoleRepresentation(keycloakRealm, client, roleName);
        Map<String, List<String>> existingAttributes = role.getAttributes() != null ? role.getAttributes() : new HashMap<>();
        existingAttributes.putAll(roleAttributes);
        role.setAttributes(existingAttributes);
        getClientResource(keycloakRealm, client).roles().get(roleName).update(role);
        log.info("Atributos actualizados correctamente para el rol '{}'.", roleName);
    }

    public void removeClientRoleAttribute(String realm, String client, String roleName, String attributeName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando eliminar el atributo '{}' del rol de cliente '{}' en el cliente '{}' del realm '{}'.", attributeName, roleName, client, keycloakRealm);
        RoleRepresentation role = getClientRoleRepresentation(keycloakRealm, client, roleName);
        if (role.getAttributes() == null || !role.getAttributes().containsKey(attributeName)) {
            throw new IllegalArgumentException("El atributo '" + attributeName + "' no existe en el rol de cliente '" + roleName + "'.");
        }
        role.getAttributes().remove(attributeName);
        getClientResource(keycloakRealm, client).roles().get(roleName).update(role);
        log.info("Atributo '{}' eliminado correctamente del rol '{}'.", attributeName, roleName);
    }

    // --- Métodos de Utilidad ---

    private ClientResource getClientResource(String keycloakRealm, String clientId) {
        ClientsResource clientsResource = utilsAdminService.getRealmResource(keycloakRealm).clients();
        return clientsResource.get(findClientId(clientsResource, clientId));
    }

    private String findClientId(ClientsResource clientsResource, String clientId) {
        return clientsResource.findByClientId(clientId).stream()
                .findFirst()
                .orElseThrow(() -> new NotFoundException("Cliente '" + clientId + "' no encontrado."))
                .getId();
    }

    private RoleRepresentation getClientRoleRepresentation(String realm, String client, String roleName) {
        log.debug("Obteniendo RoleRepresentation para el rol de cliente '{}' en el cliente '{}' del realm '{}'", roleName, client, realm);
        try {
            return getClientResource(realm, client)
                    .roles()
                    .get(roleName)
                    .toRepresentation();
        } catch (NotFoundException e) {
            throw new NotFoundException("Rol de cliente '" + roleName + "' no encontrado en el cliente '" + client + "'.");
        }
    }
}