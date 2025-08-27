package com.example.keycloak.multitenant.service.keycloak;


import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de bajo nivel para interactuar directamente con la API de administracion de Keycloak
 * y gestionar las operaciones relacionadas con los roles.
 * <p>
 * Este servicio encapsula la logica de comunicacion con el cliente de administracion de Keycloak
 * para operaciones como la creacion, eliminacion, obtencion y actualizacion de roles de realm.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakRoleService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakRoleService.class);
    private final KeycloakAdminService utilsAdminService;
    private final KeycloakConfigService utilsConfigService;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param utilsAdminService  Servicio para obtener el cliente de administracion y el recurso del realm.
     * @param utilsConfigService Servicio de utilidades para la resolucion de nombres de realm.
     */
    public KeycloakRoleService(KeycloakAdminService utilsAdminService, KeycloakConfigService utilsConfigService) {
        this.utilsAdminService = utilsAdminService;
        this.utilsConfigService = utilsConfigService;
        log.info("KeycloakRoleService inicializado.");
    }

    /**
     * Obtiene una lista de todos los roles de realm disponibles en un realm de Keycloak.
     *
     * @param realm El nombre del realm de Keycloak a consultar.
     * @return Una lista de objetos {@link RoleRepresentation} que representan los roles.
     * @throws RuntimeException Si la obtencion de roles falla en Keycloak.
     */
    public List<RoleRepresentation> getRoles(String realm) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando obtener todos los roles del realm '{}'.", keycloakRealm);

        RealmResource realmResource = utilsAdminService.getRealmResource(keycloakRealm);

        try {
            List<RoleRepresentation> roles = realmResource.roles().list();
            log.info("Se obtuvieron {} roles del realm '{}'.", roles.size(), keycloakRealm);
            return roles;
        } catch (Exception e) {
            log.error("Excepción inesperada al intentar obtener roles del realm '{}': {}", keycloakRealm, e.getMessage(), e);
            throw new RuntimeException("Error inesperado al obtener roles: " + e.getMessage(), e);
        }
    }

    /**
     * Crea un nuevo rol en un realm especifico de Keycloak.
     *
     * @param realm   El nombre del realm de Keycloak.
     * @param request El objeto {@link CreateRoleRequest} con los datos del rol a crear.
     * @throws KeycloakRoleCreationException Si el rol ya existe o si hay un error al comunicarse con Keycloak.
     */
    public void createRole(String realm, CreateRoleRequest request) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando crear el rol '{}' en el realm '{}'.", request.name(), keycloakRealm);
        log.debug("Datos del rol para creación: nombre='{}', descripción='{}'", request.name(), request.description());

        RoleRepresentation role = new RoleRepresentation();
        role.setName(request.name());
        role.setDescription(request.description());
        role.setClientRole(false); //rol de realm no de cliente

        RealmResource realmResource = utilsAdminService.getRealmResource(keycloakRealm);

        boolean rolExist = realmResource.roles().list().stream().anyMatch(
                r -> r.getName().equals((role.getName())));

        if (!rolExist) {
            try {
                realmResource.roles().create(role);
            } catch (WebApplicationException e) {

                Response response = e.getResponse();
                String errorMessage;

                if (response != null) {
                    int statusCode = response.getStatus();
                    errorMessage = response.readEntity(String.class);

                    log.error("Error al crear el rol '{}'. Estado HTTP: {}, Detalles: {}", request.name(), statusCode, errorMessage);
                    throw new KeycloakRoleCreationException("Error al crear el rol en Keycloak. Estado HTTP: " + statusCode + ". Detalles: " + errorMessage);
                }

                log.error("Error inesperado al intentar crear el rol '{}' en Keycloak: {}", request.name(), e.getMessage(), e);
                throw new RuntimeException("Error inesperado al crear el rol: " + e.getMessage(), e);

            } catch (Exception e) {
                log.error("Exception inesperado al intentar crear el rol '{}' en Keycloak: {}", request.name(), e.getMessage(), e);
                throw new RuntimeException("Error inesperado al crear el rol: " + e.getMessage(), e);
            }
        } else {
            log.error("Fallo, role '{}' ya existe en Keycloak.", request.name());
            throw new KeycloakRoleCreationException("El rol '" + request.name() + "' ya existe en el realm '" + keycloakRealm + "'.");
        }
    }

    /**
     * Elimina un rol por su nombre en un realm especifico de Keycloak.
     *
     * @param realm    El nombre del realm de Keycloak donde se eliminara el rol.
     * @param roleName El nombre del rol a eliminar.
     * @throws NotFoundException Si el rol no se encuentra.
     * @throws RuntimeException  Si la eliminacion del rol falla en Keycloak.
     */
    public void deleteRole(String realm, String roleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando eliminar el rol '{}' del realm '{}'.", roleName, keycloakRealm);

        RealmResource realmResource = utilsAdminService.getRealmResource(keycloakRealm);
        boolean rolExist = realmResource.roles().list().stream().anyMatch(
                r -> r.getName().equals(roleName));

        if (rolExist) {
            try {
                realmResource.roles().deleteRole(roleName);
            } catch (Exception e) {
                log.error("Excepción inesperada al intentar eliminar el rol '{}' del realm '{}': {}", roleName, keycloakRealm, e.getMessage(), e);
                throw new RuntimeException("Error inesperado al eliminar el rol: " + e.getMessage(), e);
            }
        } else {
            log.warn("El rol '{}' no fue encontrado en el realm '{}' para eliminación.", roleName, keycloakRealm);
            throw new NotFoundException("Rol '" + roleName + "' no encontrado en el realm '" + keycloakRealm + "'.");
        }
    }

    /**
     * Comprueba si un rol especificado en una solicitud de usuario existe en el realm.
     *
     * @param realm   El nombre del realm.
     * @param request El objeto {@link UserRequest} que contiene el nombre del rol a verificar.
     * @throws IllegalArgumentException Si el rol no existe en el realm.
     */
    public void checkRole(String realm, UserRequest request) {
        List<RoleRepresentation> roles = getRoles(realm);

        String roleName = request.role();

        boolean roleExists = roleName == null || roleName.isBlank() ||
                roles.stream().anyMatch(r -> roleName.equals(r.getName()));

        if (!roleExists) {
            log.warn("Error: El role '{}' no existe para el realm '{}'.", roleName, realm);
            throw new IllegalArgumentException("El role '" + roleName + "' no existe.");
        }
    }

    /**
     * Obtiene los atributos de un rol en un realm de Keycloak.
     *
     * @param realm    El nombre del realm de Keycloak.
     * @param roleName El nombre del rol a consultar.
     * @return Un mapa de atributos y sus valores asociados.
     * @throws NotFoundException Si el rol no se encuentra.
     * @throws RuntimeException  Si el rol no tiene atributos.
     */
    public Map<String, List<String>> getRoleAttributes(String realm, String roleName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Obteniendo atributos del rol '{}' en el realm '{}'.", roleName, keycloakRealm);

        RoleRepresentation role = getRoleRepresentation(keycloakRealm, roleName);

        if (role.getAttributes() == null || role.getAttributes().isEmpty()) {
            log.warn("El rol '{}' no tiene atributos en el realm '{}'.", roleName, keycloakRealm);
            throw new RuntimeException("El rol " + roleName + " no tien atributos.");
        }

        log.debug("Atributos obtenidos del rol '{}': {}", roleName, role.getAttributes());
        return role.getAttributes();
    }

    /**
     * Añade o actualiza los atributos de un rol en un realm.
     *
     * @param realm          El nombre del realm.
     * @param roleName       El nombre del rol.
     * @param roleAttributes Un mapa con los atributos a añadir o actualizar.
     * @throws IllegalArgumentException Si el mapa de atributos es nulo o esta vacio.
     * @throws NotFoundException        Si el rol no se encuentra.
     */
    public void addOrUpdateRoleAttributes(String realm, String roleName, Map<String, List<String>> roleAttributes) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);

        log.info("Actualizando atributos para el rol '{}' en el realm '{}'.", roleName, keycloakRealm);

        if (roleAttributes == null || roleAttributes.isEmpty()) {
            log.warn("El mapa de atributos está vacío para el rol '{}' en el realm '{}'.", roleName, keycloakRealm);
            throw new IllegalArgumentException("El mapa de atributos no puede estar vacío.");
        }

        RoleRepresentation role = getRoleRepresentation(keycloakRealm, roleName);

        if (role == null) {
            log.error("Rol '{}' no encontrado en el realm '{}'.", roleName, keycloakRealm);
            throw new RuntimeException("Rol no encontrado: " + roleName);
        }

        Map<String, List<String>> existingAttributes = role.getAttributes();
        if (existingAttributes == null) {
            existingAttributes = new HashMap<>();
            log.debug("Inicializando atributos para el rol '{}'.", roleName);
        }

        for (Map.Entry<String, List<String>> entry : roleAttributes.entrySet()) {
            String key = entry.getKey();
            List<String> value = entry.getValue();

            if (!existingAttributes.containsKey(key)) {
                log.debug("Añadiendo nuevo atributo '{}' con valores '{}'", key, value);
            } else {
                log.debug("Actualizando atributo existente '{}' con valores '{}'", key, value);
            }

            existingAttributes.put(key, value);
        }

        role.setAttributes(existingAttributes);
        utilsAdminService.getRealmResource(keycloakRealm).roles().get(roleName).update(role);

        log.info("Atributos actualizados correctamente para el rol '{}' en el realm '{}'.", roleName, keycloakRealm);
    }

    /**
     * Elimina un atributo especifico de un rol dentro de un realm.
     *
     * @param realm         Nombre del tenant (realm).
     * @param roleName      Nombre del rol en Keycloak.
     * @param attributeName Nombre del atributo a eliminar.
     * @throws NotFoundException        Si el rol no se encuentra.
     * @throws IllegalArgumentException Si el atributo especificado no existe en el rol.
     */
    public void removeRoleAttribute(String realm, String roleName, String attributeName) {
        String keycloakRealm = utilsConfigService.resolveRealm(realm);
        log.info("Intentando eliminar el atributo '{}' del rol '{}' en el realm '{}'.", attributeName, roleName, keycloakRealm);

        try {
            RoleRepresentation role = getRoleRepresentation(keycloakRealm, roleName);
            Map<String, List<String>> attributes = role.getAttributes();

            if (attributes == null || !attributes.containsKey(attributeName)) {
                log.warn("El atributo '{}' no existe en el rol '{}' del realm '{}'.", attributeName, roleName, keycloakRealm);
                throw new IllegalArgumentException("El atributo '" + attributeName + "' no existe en el rol '" + roleName + "'.");
            }

            attributes.remove(attributeName);
            role.setAttributes(attributes);
            utilsAdminService.getRealmResource(keycloakRealm).roles().get(roleName).update(role);

            log.info("Atributo '{}' eliminado del rol '{}' en realm '{}' correctamente.", attributeName, roleName, keycloakRealm);
        } catch (NotFoundException e) {
            log.error("Rol '{}' no encontrado en el realm '{}' para la eliminacion de atributos.", roleName, keycloakRealm);
            throw new NotFoundException("Rol no encontrado: " + roleName);
        }
    }

    /**
     * Metodo privado para obtener la representacion de un rol de Keycloak.
     * <p>
     * Este metodo lanza una {@link NotFoundException} si el rol no existe.
     *
     * @param realm    El nombre del realm.
     * @param roleName El nombre del rol.
     * @return Un objeto {@link RoleRepresentation} del rol solicitado.
     * @throws NotFoundException Si el rol no se encuentra en el realm especificado.
     */
    private RoleRepresentation getRoleRepresentation(String realm, String roleName) {
        log.debug("Obteniendo RoleRepresentation para '{}' en el realm '{}'", roleName, realm);
        try {
            return utilsAdminService.getRealmResource(realm)
                    .roles()
                    .get(roleName)
                    .toRepresentation();
        } catch (NotFoundException e) {
            throw new NotFoundException("Rol '" + roleName + "' no encontrado en el realm '" + realm + "'.");
        }
    }
}
