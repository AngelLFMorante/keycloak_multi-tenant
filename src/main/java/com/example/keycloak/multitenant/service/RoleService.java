package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakRoleService;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUtilsService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    private static final Logger log = LoggerFactory.getLogger(RoleService.class);

    private final KeycloakRoleService keycloakRoleService;
    private final KeycloakUtilsService utilsService;

    public RoleService(KeycloakRoleService keycloakRoleService, KeycloakUtilsService utilsService) {
        this.keycloakRoleService = keycloakRoleService;
        this.utilsService = utilsService;
    }

    /**
     * Obtiene roles de un realm basado en el nombre del tenant.
     *
     * @param realm Nombre del tenant público.
     * @return Lista de roles.
     */
    public List<RoleRepresentation> getRolesByRealm(String realm) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        return keycloakRoleService.getRoles(keycloakRealm);
    }

    /**
     * Crea un rol en el realm correspondiente al tenant.
     *
     * @param realm   Nombre del tenant.
     * @param request Datos del rol.
     * @return Respuesta con mensaje y detalles.
     */
    public Map<String, Object> createRoleInRealm(String realm, CreateRoleRequest request) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        keycloakRoleService.createRole(keycloakRealm, request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol creado exitosamente");
        response.put("roleName", request.getName());
        response.put("realm", realm);

        return response;
    }

    /**
     * Elimina un rol del realm correspondiente.
     *
     * @param realm    Nombre del tenant.
     * @param roleName Nombre del rol.
     * @return Respuesta con mensaje.
     */
    public Map<String, Object> deleteRoleFromRealm(String realm, String roleName) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        keycloakRoleService.deleteRole(keycloakRealm, roleName);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol eliminado exitosamente");
        response.put("roleName", roleName);
        response.put("realm", realm);

        return response;
    }

    /**
     * Obtiene los atributos de un rol en un realm.
     *
     * @param realm    Nombre del tenant.
     * @param roleName Nombre del role.
     * @return Atributos del rol.
     */
    public Map<String, List<String>> getRoleAttributes(String realm, String roleName) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        return keycloakRoleService.getRoleAttributes(keycloakRealm, roleName);
    }

    /**
     * Añadir o actualizar los atributos de un rol en un realm
     *
     * @param realm          Nombre del tenant
     * @param roleName       Nombre del role.
     * @param roleAttributes atributos del role
     */
    public void addOrUpdateRoleAttributes(String realm, String roleName, Map<String, List<String>> roleAttributes) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        log.info("Añadiendo/actualizando atributos en el rol '{}' del realm '{}'.", roleName, keycloakRealm);
        keycloakRoleService.addOrUpdateRoleAttributes(keycloakRealm, roleName, roleAttributes);
    }
}
