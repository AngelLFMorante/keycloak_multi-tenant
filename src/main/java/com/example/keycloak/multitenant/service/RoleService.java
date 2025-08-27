package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakRoleService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio para gestionar las operaciones de roles de Keycloak a nivel de negocio.
 * Actúa como una capa de abstracción entre el controlador y el servicio de bajo nivel
 * de Keycloak, manejando la lógica específica del dominio de roles.
 *
 * @author Angel Fm
 * @version 1.1
 */
@Service
public class RoleService {

    private static final Logger log = LoggerFactory.getLogger(RoleService.class);

    private final KeycloakRoleService keycloakRoleService;

    /**
     * Constructor para inyeccion de dependencias.
     *
     * @param keycloakRoleService El servicio de bajo nivel para interactuar con la API de Keycloak.
     */
    public RoleService(KeycloakRoleService keycloakRoleService) {
        this.keycloakRoleService = keycloakRoleService;
        log.info("RoleService inicializado.");
    }

    /**
     * Obtiene todos los roles de un realm basado en el nombre del tenant.
     *
     * @param realm El nombre del tenant público.
     * @return Una {@link List} de {@link RoleRepresentation} con todos los roles del realm.
     */
    public List<RoleRepresentation> getRolesByRealm(String realm) {
        log.info("Buscando todos los roles del realm '{}'.", realm);
        List<RoleRepresentation> roles = keycloakRoleService.getRoles(realm);
        log.debug("Se encontraron {} roles en el realm '{}'.", roles.size(), realm);
        return roles;
    }

    /**
     * Crea un nuevo rol a nivel de realm en el tenant especificado.
     *
     * @param realm   El nombre del tenant público.
     * @param request El objeto {@link CreateRoleRequest} que contiene los datos del rol a crear.
     * @return Un mapa que confirma la creación exitosa y proporciona detalles del rol.
     * @throws com.example.keycloak.multitenant.exception.KeycloakRoleCreationException Si el rol ya existe o hay un error al crearlo.
     */
    public Map<String, Object> createRoleInRealm(String realm, CreateRoleRequest request) {
        log.info("Iniciando la creación del rol '{}' en el realm '{}'.", request.name(), realm);
        keycloakRoleService.createRole(realm, request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol creado exitosamente");
        response.put("roleName", request.name());
        response.put("realm", realm);

        log.info("Rol '{}' creado exitosamente en el realm '{}'.", request.name(), realm);
        return response;
    }

    /**
     * Elimina un rol a nivel de realm por su nombre en el tenant especificado.
     *
     * @param realm    El nombre del tenant público.
     * @param roleName El nombre del rol a eliminar.
     * @return Un mapa que confirma la eliminación exitosa.
     * @throws jakarta.ws.rs.NotFoundException Si el rol no se encuentra en el realm.
     * @throws RuntimeException                Si ocurre un error inesperado al eliminar el rol.
     */
    public Map<String, Object> deleteRoleFromRealm(String realm, String roleName) {
        log.info("Iniciando la eliminación del rol '{}' del realm '{}'.", roleName, realm);
        keycloakRoleService.deleteRole(realm, roleName);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rol eliminado exitosamente");
        response.put("roleName", roleName);
        response.put("realm", realm);

        log.info("Rol '{}' eliminado exitosamente del realm '{}'.", roleName, realm);
        return response;
    }

    /**
     * Obtiene los atributos de un rol de realm en un tenant.
     *
     * @param realm    El nombre del tenant público.
     * @param roleName El nombre del rol.
     * @return Un mapa de atributos y sus valores.
     * @throws RuntimeException Si el rol no tiene atributos o si el rol no se encuentra.
     */
    public Map<String, List<String>> getRoleAttributes(String realm, String roleName) {
        log.info("Buscando atributos para el rol '{}' en el realm '{}'.", roleName, realm);
        Map<String, List<String>> attributes = keycloakRoleService.getRoleAttributes(realm, roleName);
        log.debug("Atributos obtenidos para el rol '{}': {}", roleName, attributes);
        return attributes;
    }

    /**
     * Añade o actualiza atributos en un rol de realm en un tenant.
     *
     * @param realm          El nombre del tenant público.
     * @param roleName       El nombre del rol.
     * @param roleAttributes Un mapa de atributos a añadir o actualizar.
     * @throws IllegalArgumentException Si el mapa de atributos está vacío.
     * @throws RuntimeException         Si el rol no se encuentra o hay un error al actualizar.
     */
    public void addOrUpdateRoleAttributes(String realm, String roleName, Map<String, List<String>> roleAttributes) {
        log.info("Iniciando la adición/actualización de atributos en el rol '{}' del realm '{}'.", roleName, realm);
        keycloakRoleService.addOrUpdateRoleAttributes(realm, roleName, roleAttributes);
        log.info("Atributos actualizados exitosamente en el rol '{}'.", roleName);
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
        log.info("Eliminando el atributo '{}' del rol '{}' en el realm '{}'.", attributeName, roleName, realm);
        keycloakRoleService.removeRoleAttribute(realm, roleName, attributeName);
        log.info("Atributo '{}' eliminado exitosamente del rol '{}'.", attributeName, roleName);
    }

}
