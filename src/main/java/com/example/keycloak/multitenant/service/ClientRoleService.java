package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakClientRoleService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para gestionar las operaciones de roles de cliente a nivel de negocio.
 * Actúa como una capa de abstracción sobre el servicio de bajo nivel de Keycloak.
 */
@Service
public class ClientRoleService {

    private static final Logger log = LoggerFactory.getLogger(ClientRoleService.class);

    private final KeycloakClientRoleService keycloakClientRoleService;

    public ClientRoleService(KeycloakClientRoleService keycloakClientRoleService) {
        this.keycloakClientRoleService = keycloakClientRoleService;
        log.info("ClientRoleService inicializado.");
    }

    /**
     * Obtiene todos los roles de un cliente específico en un tenant.
     */
    public List<RoleRepresentation> getClientRoles(String realm, String client) {
        log.info("Buscando todos los roles del cliente '{}' en el realm '{}'.", client, realm);
        List<RoleRepresentation> roles = keycloakClientRoleService.getClientRoles(realm, client);
        log.debug("Se encontraron {} roles para el cliente '{}'.", roles.size(), client);
        return roles;
    }

    /**
     * Crea un nuevo rol de cliente.
     */
    public Map<String, Object> createClientRole(String realm, String client, CreateRoleRequest request) {
        log.info("Iniciando la creación del rol de cliente '{}' en el cliente '{}' del realm '{}'.", request.name(), client, realm);
        keycloakClientRoleService.createClientRole(realm, client, request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol de cliente creado exitosamente");
        response.put("roleName", request.name());
        response.put("realm", realm);
        response.put("client", client);

        log.info("Rol de cliente '{}' creado exitosamente.", request.name());
        return response;
    }

    /**
     * Elimina un rol de cliente por su nombre.
     */
    public Map<String, Object> deleteClientRole(String realm, String client, String roleName) {
        log.info("Iniciando la eliminación del rol de cliente '{}' del cliente '{}' en el realm '{}'.", roleName, client, realm);
        keycloakClientRoleService.deleteClientRole(realm, client, roleName);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol de cliente eliminado exitosamente");
        response.put("roleName", roleName);
        response.put("realm", realm);
        response.put("client", client);

        log.info("Rol de cliente '{}' eliminado exitosamente.", roleName);
        return response;
    }

    /**
     * Comprueba si un rol de cliente existe en el cliente.
     */
    public void checkClientRole(String realm, String client, UserRequest request) {
        List<RoleRepresentation> roles = getClientRoles(realm, client);
        String roleName = request.role();

        boolean roleExists = roleName == null || roleName.isBlank() ||
                roles.stream().anyMatch(r -> roleName.equals(r.getName()));

        if (!roleExists) {
            log.warn("Error: El role '{}' no existe para el cliente '{}' en el realm '{}'.", roleName, client, realm);
            throw new IllegalArgumentException("El role '" + roleName + "' no existe para el cliente '" + client + "'.");
        }
    }

    /**
     * Obtiene los atributos de un rol de cliente.
     */
    public Map<String, List<String>> getClientRoleAttributes(String realm, String client, String roleName) {
        log.info("Buscando atributos para el rol de cliente '{}' en el cliente '{}' del realm '{}'.", roleName, client, realm);
        Map<String, List<String>> attributes = keycloakClientRoleService.getClientRoleAttributes(realm, client, roleName);
        log.debug("Atributos obtenidos para el rol '{}': {}", roleName, attributes);
        return attributes;
    }

    /**
     * Añade o actualiza atributos en un rol de cliente.
     */
    public void addOrUpdateClientRoleAttributes(String realm, String client, String roleName, Map<String, List<String>> roleAttributes) {
        log.info("Iniciando la adición/actualización de atributos en el rol '{}' del cliente '{}' del realm '{}'.", roleName, client, realm);
        keycloakClientRoleService.addOrUpdateClientRoleAttributes(realm, client, roleName, roleAttributes);
        log.info("Atributos actualizados exitosamente en el rol '{}'.", roleName);
    }

    /**
     * Elimina un atributo específico de un rol de cliente.
     */
    public void removeClientRoleAttribute(String realm, String client, String roleName, String attributeName) {
        log.info("Eliminando el atributo '{}' del rol '{}' en el cliente '{}' del realm '{}'.", attributeName, roleName, client, realm);
        keycloakClientRoleService.removeClientRoleAttribute(realm, client, roleName, attributeName);
        log.info("Atributo '{}' eliminado exitosamente del rol '{}'.", attributeName, roleName);
    }
}