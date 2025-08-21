package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.RoleService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para gestionar las operaciones de roles en Keycloak.
 * Proporcioina endpoints para crear, eliminar, obtener y actualizar roles.
 */
@RestController
@RequestMapping("/api/v1")
public class RoleController {

    private static final Logger log = LoggerFactory.getLogger(RoleController.class);

    private final RoleService roleService;

    /**
     * Constructor pra inyeccion de dependencias
     *
     * @param roleService roleService
     */
    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    /**
     * Obtiene todos los roles para un tenant específico.
     *
     * @param realm Nombre del tenant (mapeado a un realm Keycloak).
     * @return Lista de roles del realm.
     */
    @GetMapping("/{realm}/roles")
    public ResponseEntity<List<RoleRepresentation>> getRoles(@PathVariable String realm) {
        log.info("Solicitud GET para obtener roles del tenant '{}'", realm);
        List<RoleRepresentation> roles = roleService.getRolesByRealm(realm);
        return ResponseEntity.ok(roles);
    }

    /**
     * Crea un nuevo rol en el tenant especificado.
     *
     * @param realm   Nombre del tenant (mapeado a un realm Keycloak).
     * @param request Datos del rol a crear.
     * @return Respuesta con estado y detalles.
     */
    @PostMapping("/{realm}/roles")
    public ResponseEntity<Map<String, Object>> createRole(@PathVariable String realm,
                                                          @Valid @RequestBody CreateRoleRequest request) {
        log.info("Solicitud POST para crear rol '{}' en tenant '{}'", request.getName(), realm);
        Map<String, Object> response = roleService.createRoleInRealm(realm, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Elimina un rol por nombre en el tenant especificado.
     *
     * @param realm    Nombre del tenant.
     * @param roleName Nombre del rol a eliminar.
     * @return Mensaje de confirmación.
     */
    @DeleteMapping("/{realm}/roles/{roleName}")
    public ResponseEntity<Map<String, Object>> deleteRole(@PathVariable String realm,
                                                          @PathVariable String roleName) {
        log.info("Solicitud DELETE para eliminar rol '{}' en tenant '{}'", roleName, realm);
        Map<String, Object> response = roleService.deleteRoleFromRealm(realm, roleName);
        return ResponseEntity.ok(response);
    }

    /**
     * Obtiene atributos asociados a un rol específico.
     *
     * @param realm    Nombre del tenant.
     * @param roleName Nombre del rol.
     * @return Mapa de atributos.
     */
    @GetMapping("/{realm}/roles/{roleName}/attributes")
    public ResponseEntity<Map<String, List<String>>> getRoleAttributes(@PathVariable String realm,
                                                                       @PathVariable String roleName) {
        log.info("Solicitud GET para atributos del rol '{}' en tenant '{}'", roleName, realm);
        Map<String, List<String>> attributes = roleService.getRoleAttributes(realm, roleName);
        return ResponseEntity.ok(attributes);
    }

    /**
     * Añade o actualiza atributos en un rol específico dentro de un realm.
     *
     * @param realm          Nombre lógico del tenant (mapeado a un realm de Keycloak).
     * @param roleName       Nombre del rol en Keycloak.
     * @param roleAttributes Mapa de atributos a añadir o actualizar.
     * @return ResponseEntity sin contenido en caso de éxito.
     */
    @PutMapping("/{roleName}/attributes")
    public ResponseEntity<Void> addOrUpdateRoleAttributes(@PathVariable String realm, @PathVariable String roleName, @RequestBody Map<String, List<String>> roleAttributes) {
        log.info("Solicitud para añadir/actualizar atributos del rol '{}' en el realm '{}'.", roleName, realm);

        roleService.addOrUpdateRoleAttributes(realm, roleName, roleAttributes);
        log.info("Atributos añadidos/actualizados correctamente para el rol '{}' en el realm '{}'.", roleName, realm);

        return ResponseEntity.noContent().build();
    }
}
