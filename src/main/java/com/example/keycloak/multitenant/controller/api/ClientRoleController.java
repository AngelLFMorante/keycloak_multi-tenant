package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.ClientRoleService;
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
 * Controlador REST para gestionar las operaciones de roles de cliente en Keycloak.
 * <p>
 * Proporciona endpoints para crear, eliminar, obtener y actualizar roles
 * de cliente para un cliente específico dentro de un tenant.
 */
@RestController
@RequestMapping("/api/v1/{realm}/clients/{client}")
@Tag(name = "Client Role Management", description = "Operaciones para la gestion de roles de cliente de Keycloak.")
public class ClientRoleController {

    private static final Logger log = LoggerFactory.getLogger(ClientRoleController.class);

    private final ClientRoleService clientRoleService;

    /**
     * Constructor para inyeccion de dependencias.
     */
    public ClientRoleController(ClientRoleService clientRoleService) {
        this.clientRoleService = clientRoleService;
    }

    /**
     * Obtiene todos los roles de cliente para un cliente y tenant específicos.
     *
     * @param realm  El identificador del tenant (realm).
     * @param client El ID del cliente de Keycloak.
     * @return Una {@link ResponseEntity} que contiene una lista de roles de cliente.
     */
    @Operation(
            summary = "Obtiene todos los roles de cliente de un cliente.",
            description = "Devuelve una lista de todos los roles de cliente para el cliente y tenant especificados."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Roles de cliente obtenidos exitosamente.",
                    content = @Content(schema = @Schema(implementation = RoleRepresentation[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant o cliente no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/roles")
    public ResponseEntity<List<RoleRepresentation>> getClientRoles(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @PathVariable String client) {
        log.info("Solicitud GET para obtener roles del cliente '{}' en el tenant '{}'", client, realm);
        List<RoleRepresentation> roles = clientRoleService.getClientRoles(realm, client);
        return ResponseEntity.ok(roles);
    }

    /**
     * Crea un nuevo rol de cliente en el cliente y tenant especificados.
     *
     * @param realm   El identificador del tenant (realm).
     * @param client  El ID del cliente de Keycloak.
     * @param request Datos del rol a crear, incluyendo nombre y descripción.
     * @return Una {@link ResponseEntity} con el estado de la operación y un mensaje de éxito.
     */
    @Operation(
            summary = "Crea un nuevo rol de cliente.",
            description = "Crea un rol de cliente en Keycloak para el cliente y tenant especificados."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Rol de cliente creado exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "400", description = "Error de validación en los datos del rol.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o cliente no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "El rol de cliente ya existe.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/roles")
    public ResponseEntity<Map<String, Object>> createClientRole(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @PathVariable String client,
            @Valid @RequestBody CreateRoleRequest request) {
        log.info("Solicitud POST para crear rol '{}' en el cliente '{}' del tenant '{}'", request.name(), client, realm);
        Map<String, Object> response = clientRoleService.createClientRole(realm, client, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Elimina un rol de cliente por nombre en el cliente y tenant especificados.
     *
     * @param realm    El identificador del tenant (realm).
     * @param client   El ID del cliente de Keycloak.
     * @param roleName El nombre del rol a eliminar.
     * @return Una {@link ResponseEntity} con un mensaje de confirmación de la eliminación.
     */
    @Operation(
            summary = "Elimina un rol de cliente por nombre.",
            description = "Elimina el rol de cliente con el nombre especificado del cliente de Keycloak."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Rol de cliente eliminado exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "404", description = "Tenant, cliente o rol de cliente no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/roles/{roleName}")
    public ResponseEntity<Map<String, Object>> deleteClientRole(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @PathVariable String client,
            @Parameter(description = "El nombre del rol de cliente a eliminar.")
            @PathVariable String roleName) {
        log.info("Solicitud DELETE para eliminar rol '{}' del cliente '{}' en el tenant '{}'", roleName, client, realm);
        Map<String, Object> response = clientRoleService.deleteClientRole(realm, client, roleName);
        return ResponseEntity.ok(response);
    }

    // --- Otros Endpoints de ClientRoleController ---

    /**
     * Obtiene los atributos asociados a un rol de cliente específico.
     *
     * @param realm    El identificador del tenant (realm).
     * @param client   El ID del cliente de Keycloak.
     * @param roleName El nombre del rol.
     * @return Una {@link ResponseEntity} que contiene un mapa de atributos del rol.
     */
    @Operation(
            summary = "Obtiene los atributos de un rol de cliente.",
            description = "Devuelve un mapa de atributos asociados a un rol de cliente específico."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Atributos del rol obtenidos exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "404", description = "Tenant, cliente o rol de cliente no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/roles/{roleName}/attributes")
    public ResponseEntity<Map<String, List<String>>> getClientRoleAttributes(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @PathVariable String client,
            @Parameter(description = "El nombre del rol de cliente.")
            @PathVariable String roleName) {
        log.info("Solicitud GET para atributos del rol '{}' del cliente '{}' en el tenant '{}'", roleName, client, realm);
        Map<String, List<String>> attributes = clientRoleService.getClientRoleAttributes(realm, client, roleName);
        return ResponseEntity.ok(attributes);
    }

    /**
     * Añade o actualiza atributos en un rol de cliente específico.
     *
     * @param realm          El identificador del tenant (realm).
     * @param client         El ID del cliente de Keycloak.
     * @param roleName       El nombre del rol de cliente a actualizar.
     * @param roleAttributes Mapa de atributos a añadir o actualizar.
     * @return Una {@link ResponseEntity} sin contenido en caso de éxito.
     */
    @Operation(
            summary = "Añade o actualiza atributos en un rol de cliente.",
            description = "Añade nuevos atributos o actualiza los existentes en un rol de cliente específico."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Atributos añadidos/actualizados exitosamente."),
            @ApiResponse(responseCode = "400", description = "Petición inválida, el mapa de atributos está vacío.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant, cliente o rol de cliente no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PutMapping("/roles/{roleName}/attributes")
    public ResponseEntity<Void> addOrUpdateClientRoleAttributes(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @PathVariable String client,
            @Parameter(description = "El nombre del rol de cliente a actualizar.")
            @PathVariable String roleName,
            @RequestBody Map<String, List<String>> roleAttributes) {
        log.info("Solicitud para añadir/actualizar atributos del rol '{}' en el cliente '{}' del realm '{}'.", roleName, client, realm);

        clientRoleService.addOrUpdateClientRoleAttributes(realm, client, roleName, roleAttributes);
        log.info("Atributos añadidos/actualizados correctamente para el rol '{}' en el cliente '{}' del realm '{}'.", roleName, client, realm);

        return ResponseEntity.noContent().build();
    }

    /**
     * Elimina un atributo específico de un rol de cliente.
     *
     * @param realm         El identificador del tenant (realm).
     * @param client        El ID del cliente de Keycloak.
     * @param roleName      El nombre del rol de cliente.
     * @param attributeName El nombre del atributo a eliminar.
     * @return Una {@link ResponseEntity} sin contenido si la operación es exitosa.
     */
    @Operation(
            summary = "Elimina un atributo de un rol de cliente.",
            description = "Elimina un atributo específico del rol de cliente indicado."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Atributo eliminado exitosamente."),
            @ApiResponse(responseCode = "404", description = "Tenant, cliente, rol o atributo no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/roles/{roleName}/attributes/{attributeName}")
    public ResponseEntity<Void> removeClientRoleAttribute(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @PathVariable String client,
            @Parameter(description = "El nombre del rol de cliente.")
            @PathVariable String roleName,
            @Parameter(description = "El nombre del atributo a eliminar.")
            @PathVariable String attributeName) {
        log.info("Solicitud DELETE para eliminar atributo '{}' del rol '{}' en el cliente '{}' del realm '{}'.",
                attributeName, roleName, client, realm);

        clientRoleService.removeClientRoleAttribute(realm, client, roleName, attributeName);
        log.info("Atributo '{}' eliminado correctamente del rol '{}' en el cliente '{}' del realm '{}'.",
                attributeName, roleName, client, realm);

        return ResponseEntity.noContent().build();
    }
}