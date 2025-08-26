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

/**
 * Servicio para gestionar las operaciones de roles de Keycloak a nivel de negocio.
 * Actua como una capa de abstraccion entre el controlador y el servicio de bajo nivel
 * de Keycloak, manejando la logica especifica del dominio de roles.
 */
@Service
public class RoleService {

    private static final Logger log = LoggerFactory.getLogger(RoleService.class);

    private final KeycloakRoleService keycloakRoleService;
    private final KeycloakUtilsService utilsService;

    /**
     * Constructor para inyeccion de dependencias.
     *
     * @param keycloakRoleService El servicio de bajo nivel para interactuar con la API de Keycloak.
     * @param utilsService        El servicio de utilidad para resolver nombres de realms.
     */
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
     * Crea un nuevo rol de realm en el tenant especificado.
     *
     * @param realm   El nombre del tenant publico.
     * @param request El objeto {@link CreateRoleRequest} que contiene los datos del rol a crear.
     * @return Un mapa que confirma la creacion exitosa y proporciona detalles del rol.
     * @throws com.example.keycloak.multitenant.exception.KeycloakRoleCreationException Si el rol ya existe o hay un error al crearlo.
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
     * Elimina un rol de realm por su nombre en el tenant especificado.
     *
     * @param realm    El nombre del tenant publico.
     * @param roleName El nombre del rol a eliminar.
     * @return Un mapa que confirma la eliminacion exitosa.
     * @throws jakarta.ws.rs.NotFoundException Si el rol no se encuentra en el realm.
     * @throws RuntimeException                Si ocurre un error inesperado al eliminar el rol.
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
     * Obtiene los atributos de un rol de realm en un tenant.
     *
     * @param realm    El nombre del tenant publico.
     * @param roleName El nombre del rol.
     * @return Un mapa de atributos y sus valores.
     * @throws RuntimeException Si el rol no tiene atributos o si el rol no se encuentra.
     */
    public Map<String, List<String>> getRoleAttributes(String realm, String roleName) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        return keycloakRoleService.getRoleAttributes(keycloakRealm, roleName);
    }

    /**
     * Anade o actualiza atributos en un rol de realm en un tenant.
     *
     * @param realm          El nombre del tenant publico.
     * @param roleName       El nombre del rol.
     * @param roleAttributes Un mapa de atributos a anadir o actualizar.
     * @throws IllegalArgumentException Si el mapa de atributos esta vacio.
     * @throws RuntimeException         Si el rol no se encuentra o hay un error al actualizar.
     */
    public void addOrUpdateRoleAttributes(String realm, String roleName, Map<String, List<String>> roleAttributes) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        log.info("Añadiendo/actualizando atributos en el rol '{}' del realm '{}'.", roleName, keycloakRealm);
        keycloakRoleService.addOrUpdateRoleAttributes(keycloakRealm, roleName, roleAttributes);
    }

    /**
     * Elimina un atributo específico de un rol dentro de un realm.
     *
     * @param realm         Nombre del tenant (realm).
     * @param roleName      Nombre del rol en Keycloak.
     * @param attributeName Nombre del atributo a eliminar.
     * @throws IllegalArgumentException si el atributo especificado no existe en el rol.
     */
    public void removeRoleAttribute(String realm, String roleName, String attributeName) {
        String keycloakRealm = utilsService.resolveRealm(realm);
        log.debug("Eliminando atributo '{}' del rol '{}' en realm '{}'.", attributeName, roleName, realm);
        keycloakRoleService.removeRoleAttribute(keycloakRealm, roleName, attributeName);
    }

}
