package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithDetailedClientRoles;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.UserClientService;
import com.example.keycloak.multitenant.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para gestionar el ciclo de vida de los usuarios en Keycloak,
 * adaptado para manejar roles de cliente.
 * <p>
 * Proporciona endpoints para registrar, obtener, actualizar y eliminar usuarios.
 * Las operaciones relacionadas con roles ahora se delegan a {@link UserClientService}.
 *
 * @author Angel Fm
 * @version 1.0
 * @see UserService
 * @see UserClientService
 */
@RestController
@RequestMapping("/api/v1/{realm}/users/client")
@Tag(name = "User Management", description = "Operaciones para la gestion de usuarios en Keycloak.")
public class UserClientController {

    private static Logger log = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;
    private final UserClientService userClientService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param userService       El servicio de usuarios que maneja la lógica de negocio general.
     * @param userClientService El servicio de usuarios que maneja la lógica de negocio de roles de cliente.
     */
    public UserClientController(UserService userService, UserClientService userClientService) {
        this.userService = userService;
        this.userClientService = userClientService;
        log.info("UserController inicializado.");
    }

    /**
     * Endpoint para obtener la lista de todos los usuarios con sus roles de cliente.
     *
     * @param realm El nombre del realm (tenant).
     * @return Una {@link ResponseEntity} que contiene una lista de {@link UserWithRoles}.
     */
    @Operation(
            summary = "Obtiene todos los usuarios con roles de cliente",
            description = "Recupera una lista de todos los usuarios en un realm de Keycloak con sus roles de cliente."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con éxito.",
                    content = @Content(schema = @Schema(implementation = UserWithRoles[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant o cliente no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping
    public ResponseEntity<List<UserWithDetailedClientRoles>> getAllUsers(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm) {
        log.info("Solicitud para obtener todos los usuarios del tenant: {} con roles.", realm);
        List<UserWithDetailedClientRoles> users = userClientService.getAllUsersWithClientRoles(realm);
        log.info("Lista de {} usuarios obtenida con éxito.", users.size());
        return ResponseEntity.ok(users);
    }


    /**
     * Endpoint para obtener un usuario por ID junto con sus roles de cliente.
     *
     * @param realm  El nombre del realm (tenant).
     * @param userId El ID del usuario en formato UUID.
     * @return Una {@link ResponseEntity} con el objeto {@link UserWithRoles}.
     */
    @Operation(
            summary = "Obtiene un usuario por su ID y sus roles de cliente",
            description = "Recupera la informacion del usuario y sus roles de cliente en una sola respuesta."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario recuperado con éxito.",
                    content = @Content(schema = @Schema(implementation = UserWithRoles.class))),
            @ApiResponse(responseCode = "404", description = "Tenant, cliente o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/{userId}")
    public ResponseEntity<UserWithDetailedClientRoles> getUserById(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del usuario a obtener.")
            @PathVariable UUID userId) {
        log.info("Iniciando solicitud para obtener el usuario con ID '{}' en el tenant '{}'.", userId, realm);
        UserWithDetailedClientRoles userDetails = userClientService.getUserById(realm, userId.toString());
        log.info("Usuario con ID '{}' y roles de cliente.", userId);
        return ResponseEntity.ok(userDetails);
    }

    /**
     * Endpoint para obtener un usuario por su email y sus roles de cliente.
     *
     * @param realm    El nombre del realm (tenant).
     * @param clientId El ID del cliente.
     * @param email    El correo electrónico del usuario a buscar.
     * @return Una {@link ResponseEntity} con el objeto {@link UserWithDetailedClientRoles}.
     */
    @Operation(
            summary = "Obtiene un usuario por su email y sus roles de cliente",
            description = "Recupera la informacion del usuario y sus roles de cliente en una sola respuesta."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario recuperado con éxito.",
                    content = @Content(schema = @Schema(implementation = UserWithRoles.class))),
            @ApiResponse(responseCode = "404", description = "Realm, cliente o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/email/{email}")
    public ResponseEntity<UserWithDetailedClientRoles> getUserByEmail(
            @Parameter(description = "El nombre del realm.")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @RequestParam(required = true) String clientId,
            @Parameter(description = "El email del usuario a obtener.")
            @PathVariable String email) {
        log.info("Iniciando solicitud para obtener el usuario con el email '{}' del cliente '{}' en el realm '{}'.", email, clientId, realm);
        UserWithDetailedClientRoles userDetails = userClientService.getUserByEmailWithClientRoles(realm, clientId, email);
        log.info("Usuario con email '{}' y roles de cliente recuperados exitosamente del cliente '{}'.", email, clientId);
        return ResponseEntity.ok(userDetails);
    }

    /**
     * Endpoint para obtener una lista de usuarios por atributos personalizados.
     * <p>
     * Este método no cambia, ya que la búsqueda por atributos es una operación de nivel
     * de usuario y no de rol de cliente.
     *
     * @param realm        El nombre del realm (tenant).
     * @param organization Atributo de la organización para filtrar.
     * @param subsidiary   Atributo de la filial para filtrar.
     * @param department   Atributo del departamento para filtrar.
     * @return Una {@link ResponseEntity} que contiene una lista de {@link UserWithRolesAndAttributes}.
     */
    @Operation(
            summary = "Obtiene usuarios por atributos personalizados",
            description = "Busca y filtra una lista de usuarios en un realm por sus atributos personalizados (organizacion, filial, departamento)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con exito.",
                    content = @Content(schema = @Schema(implementation = UserWithRolesAndAttributes[].class))),
            @ApiResponse(responseCode = "404", description = "Tenant no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/attributes")
    public ResponseEntity<List<UserWithRolesAndAttributes>> getUsersByAttributes(
            @Parameter(description = "El nombre del realm.")
            @PathVariable String realm,
            @Parameter(description = "Filtra por la organización.")
            @RequestParam(required = false) String organization,
            @Parameter(description = "Filtra por la filial.")
            @RequestParam(required = false) String subsidiary,
            @Parameter(description = "Filtra por el departamento.")
            @RequestParam(required = false) String department) {
        log.info("Solicitud de busqueda por atributos para el realm '{}'", realm);
        log.debug("Criterios de búsqueda recibidos: organizacion='{}', filial='{}', departamento='{}'.", organization, subsidiary, department);
        UserSearchCriteria criteria = new UserSearchCriteria(organization, subsidiary, department);
        List<UserWithRolesAndAttributes> users = userService.getUsersByAttributes(realm, criteria);
        log.info("Busqueda completada. {} usuarios encontrados.", users.size());
        return ResponseEntity.ok(users);
    }
}