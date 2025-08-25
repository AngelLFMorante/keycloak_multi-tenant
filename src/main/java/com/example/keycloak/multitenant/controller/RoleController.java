package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
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
@Tag(name = "Role Management", description = "Operaciones para la gestion de roles de Keycloak por tenant")
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
    @Operation(
            summary = "Obtiene todos los roles disponibles en un tenant.",
            description = "Devuelve una lista de todos los roles de realm para el tenant (realm) especificado en la URL."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de roles obtenida exitosamente.",
                    content = @Content(schema = @Schema(implementation = RoleRepresentation[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/{realm}/roles")
    public ResponseEntity<List<RoleRepresentation>> getRoles(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm) {
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
    @Operation(
            summary = "Crea un nuevo rol en un tenant.",
            description = "Crea un rol de realm en Keycloak para el tenant especificado, con un nombre y una descripcion."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Rol creado exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "400", description = "Error de validacion en los datos del rol.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "El rol ya existe.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/{realm}/roles")
    public ResponseEntity<Map<String, Object>> createRole(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
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
    @Operation(
            summary = "Elimina un rol por nombre.",
            description = "Elimina el rol de realm con el nombre especificado del tenant de Keycloak."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Rol eliminado exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o rol no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/{realm}/roles/{roleName}")
    public ResponseEntity<Map<String, Object>> deleteRole(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El nombre del rol a eliminar.")
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
    @Operation(
            summary = "Obtiene los atributos de un rol.",
            description = "Devuelve un mapa de atributos asociados a un rol específico dentro de un tenant."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Atributos del rol obtenidos exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o rol no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/{realm}/roles/{roleName}/attributes")
    public ResponseEntity<Map<String, List<String>>> getRoleAttributes(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El nombre del rol.")
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
    @Operation(
            summary = "Añade o actualiza atributos en un rol.",
            description = "Añade nuevos atributos o actualiza los existentes en un rol específico en el tenant."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Atributos añadidos/actualizados exitosamente."),
            @ApiResponse(responseCode = "400", description = "Peticion invalida, el mapa de atributos esta vacio.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o rol no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PutMapping("/{realm}/roles/{roleName}/attributes")
    public ResponseEntity<Void> addOrUpdateRoleAttributes(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El nombre del rol a actualizar.")
            @PathVariable String roleName,
            @RequestBody Map<String, List<String>> roleAttributes) {
        log.info("Solicitud para añadir/actualizar atributos del rol '{}' en el realm '{}'.", roleName, realm);

        roleService.addOrUpdateRoleAttributes(realm, roleName, roleAttributes);
        log.info("Atributos añadidos/actualizados correctamente para el rol '{}' en el realm '{}'.", roleName, realm);

        return ResponseEntity.noContent().build();
    }

    /**
     * Elimina un atributo específico de un rol dentro de un realm.
     *
     * @param realm         Nombre del tenant.
     * @param roleName      Nombre del rol en Keycloak.
     * @param attributeName Nombre del atributo a eliminar.
     * @return ResponseEntity sin contenido si la operación es exitosa.
     */
    @Operation(
            summary = "Elimina un atributo de un rol.",
            description = "Elimina un atributo específico del rol indicado dentro del tenant."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Atributo eliminado exitosamente."),
            @ApiResponse(responseCode = "404", description = "Tenant, rol o atributo no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/{realm}/roles/{roleName}/attributes/{attributeName}")
    public ResponseEntity<Void> removeRoleAttribute(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El nombre del rol.")
            @PathVariable String roleName,
            @Parameter(description = "El nombre del atributo a eliminar.")
            @PathVariable String attributeName) {

        log.info("Solicitud DELETE para eliminar atributo '{}' del rol '{}' en el realm '{}'.",
                attributeName, roleName, realm);

        roleService.removeRoleAttribute(realm, roleName, attributeName);
        log.info("Atributo '{}' eliminado correctamente del rol '{}' en el realm '{}'.",
                attributeName, roleName, realm);

        return ResponseEntity.noContent().build();
    }
}
