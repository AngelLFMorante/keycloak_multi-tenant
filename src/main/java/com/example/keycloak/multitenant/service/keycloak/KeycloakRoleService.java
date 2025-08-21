package com.example.keycloak.multitenant.service.keycloak;


import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.model.UserRequest;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class KeycloakRoleService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakRoleService.class);
    private final Keycloak keycloak;

    public KeycloakRoleService(Keycloak keycloak) {
        this.keycloak = keycloak;
        log.info("KeycloakRoleService inicializado.");
    }

    /**
     * Obtiene una lista de todos los roles de realm disponibles en un realm específico de Keycloak.
     *
     * @param realm El nombre del realm de Keycloak a consultar.
     * @return Una lista de objetos {@link RoleRepresentation} que representan los roles.
     * @throws RuntimeException Si la obtención de roles falla en Keycloak.
     */
    public List<RoleRepresentation> getRoles(String realm) {
        log.info("Intentando obtener todos los roles del realm '{}'.", realm);

        RealmResource realmResource = getRealmResource(realm)

        try {
            List<RoleRepresentation> roles = realmResource.roles().list();
            log.info("Se obtuvieron {} roles del realm '{}'.", roles.size(), realm);
            return roles;
        } catch (Exception e) {
            log.error("Excepción inesperada al intentar obtener roles del realm '{}': {}", realm, e.getMessage(), e);
            throw new RuntimeException("Error inesperado al obtener roles: " + e.getMessage(), e);
        }
    }

    /**
     * Crea un nuevo rol en un realm especifico de Keycloak
     *
     * @param realm   realm keycloak
     * @param request datos del crear role
     */
    public void createRole(String realm, CreateRoleRequest request) {
        log.info("Intentando crear el rol '{}' en el realm '{}'.", request.getName(), realm);
        log.debug("Datos del rol para creación: nombre='{}', descripción='{}'", request.getName(), request.getDescription());

        RoleRepresentation role = new RoleRepresentation();
        role.setName(request.getName());
        role.setDescription(request.getDescription());
        role.setClientRole(false); //rol de realm no de cliente

        RealmResource realmResource = getRealmResource(realm);

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

                    log.error("Error al crear el rol '{}'. Estado HTTP: {}, Detalles: {}", request.getName(), statusCode, errorMessage);
                    throw new KeycloakRoleCreationException("Error al crear el rol en Keycloak. Estado HTTP: " + statusCode + ". Detalles: " + errorMessage);
                }

                log.error("Error inesperado al intentar crear el rol '{}' en Keycloak: {}", request.getName(), e.getMessage(), e);
                throw new RuntimeException("Error inesperado al crear el rol: " + e.getMessage(), e);

            } catch (Exception e) {
                log.error("Exception inesperado al intentar crear el rol '{}' en Keycloak: {}", request.getName(), e.getMessage(), e);
                throw new RuntimeException("Error inesperado al crear el rol: " + e.getMessage(), e);
            }
        } else {
            log.error("Fallo, role '{}' ya existe en Keycloak.", request.getName());
            throw new KeycloakRoleCreationException("El rol '" + request.getName() + "' ya existe en el realm '" + realm + "'.");
        }
    }

    /**
     * Elimina un rol por su nombre en un realm especifico de keycloak
     *
     * @param realm    El nombre del realm de Keycloak donde se eliminará el rol.
     * @param roleName El nombre del rol a eliminar.
     * @throws RuntimeException  Si la eliminación del rol falla en Keycloak.
     * @throws NotFoundException Si el rol no se encuentra.
     */
    public void deleteRole(String realm, String roleName) {
        log.info("Intentando eliminar el rol '{}' del realm '{}'.", roleName, realm);

        RealmResource realmResource = getRealmResource(realm);
        boolean rolExist = realmResource.roles().list().stream().anyMatch(
                r -> r.getName().equals(roleName));

        if (rolExist) {
            try {
                realmResource.roles().deleteRole(roleName);
            } catch (Exception e) {
                log.error("Excepción inesperada al intentar eliminar el rol '{}' del realm '{}': {}", roleName, realm, e.getMessage(), e);
                throw new RuntimeException("Error inesperado al eliminar el rol: " + e.getMessage(), e);
            }
        } else {
            log.warn("El rol '{}' no fue encontrado en el realm '{}' para eliminación.", roleName, realm);
            throw new NotFoundException("Rol '" + roleName + "' no encontrado en el realm '" + realm + "'.");
        }
    }

    /**
     * Comprobar si el role existe en el realm
     *
     * @param realm   nombre del realm
     * @param request datos de usuario donde esta el role
     */
    public void checkRole(String realm, UserRequest request) {
        List<RoleRepresentation> roles = getRoles(realm);

        String roleName = request.getRole();

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
     * @param realm El nombre del realm de Keycloak.
     * @param roleName      El nombre del rol a consultar.
     * @return Mapa de atributos y sus valores asociados.
     * @throws RuntimeException Si el rol no tiene atributos.
     */
    public Map<String, List<String>> getRoleAttributes(String realm, String roleName) {
        log.info("Obteniendo atributos del rol '{}' en el realm '{}'.", roleName, realm);

        RoleRepresentation role = getRoleRepresentation(realm, roleName);

        if (role.getAttributes() == null || role.getAttributes().isEmpty()) {
            log.warn("El rol '{}' no tiene atributos en el realm '{}'.", roleName, realm);
            throw new RuntimeException("El rol " + roleName + " no tien atributos.");
        }

        log.debug("Atributos obtenidos del rol '{}': {}", roleName, role.getAttributes());
        return role.getAttributes();
    }

    public void addOrUpdateRoleAttributes(String realm, String roleName, Map<String, List<String>> roleAttributes) {
        log.info("Actualizando atributos para el rol '{}' en el realm '{}'.", roleName, realm);

        if (roleAttributes == null || roleAttributes.isEmpty()) {
            log.warn("El mapa de atributos está vacío para el rol '{}' en el realm '{}'.", roleName, realm);
            throw new IllegalArgumentException("El mapa de atributos no puede estar vacío.");
        }

        RoleRepresentation role = getRoleRepresentation(realm, roleName);

        if (role == null) {
            log.error("Rol '{}' no encontrado en el realm '{}'.", roleName, realm);
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
        getRealmResource(realm).roles().get(roleName).update(role);

        log.info("Atributos actualizados correctamente para el rol '{}' en el realm '{}'.", roleName, realm);
    }

    private RealmResource getRealmResource(String realm) {
        return keycloak.realm(realm);
    }

    private RoleRepresentation getRoleRepresentation(String realm, String roleName) {
        log.debug("Obteniendo RoleRepresentation para '{}' en el realm '{}'", roleName, realm);
        return keycloak.realm(realm)
                .roles()
                .get(roleName)
                .toRepresentation();
    }

}
