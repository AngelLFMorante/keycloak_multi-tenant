package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.PasswordRequest;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
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
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
     * Maneja las solicitudes POST para procesar el registro de un nuevo usuario.
     * <p>
     * Se ha modificado para incluir el 'clientId' como un parámetro de consulta
     * y delegar el registro con el rol de cliente al servicio apropiado.
     *
     * @param realm    El nombre del tenant (realm).
     * @param clientId El ID del cliente para asignar el rol.
     * @param request  El objeto {@link UserRequest} que contiene los datos del usuario.
     * @return Un {@link ResponseEntity} con el estado de éxito o error del registro.
     */
    @Operation(
            summary = "Registra un nuevo usuario con rol de cliente",
            description = "Crea un nuevo usuario en Keycloak y le asigna un rol de cliente especificado en la solicitud."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Usuario registrado exitosamente.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "400", description = "Datos de registro invalidos.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o cliente no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerUser(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @RequestParam(required = true) String clientId,
            @Valid @RequestBody UserRequest request) {
        log.info("Intento de registro de usuario para el tenant: {} y cliente: {}", realm, clientId);
        Map<String, Object> response = userClientService.registerUser(realm, clientId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Endpoint para obtener la lista de todos los usuarios con sus roles de cliente.
     *
     * @param realm    El nombre del realm (tenant).
     * @param clientId El ID del cliente para filtrar los roles.
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
    public ResponseEntity<List<UserWithRoles>> getAllUsers(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @RequestParam(required = true) String clientId) {
        log.info("Solicitud para obtener todos los usuarios del tenant: {} con roles del cliente: {}", realm, clientId);
        List<UserWithRoles> users = userClientService.getAllUsersWithClientRoles(realm, clientId);
        log.info("Lista de {} usuarios obtenida con éxito.", users.size());
        return ResponseEntity.ok(users);
    }

    /**
     * Endpoint para actualizar un usuario por su ID, incluyendo su rol de cliente.
     *
     * @param realm       El nombre del realm (tenant).
     * @param clientId    El ID del cliente para actualizar el rol.
     * @param userId      El ID del usuario a actualizar.
     * @param updatedUser Los datos del usuario actualizados.
     * @return Una {@link ResponseEntity} vacía con estado OK.
     */
    @Operation(
            summary = "Actualiza un usuario y su rol de cliente",
            description = "Actualiza la informacion de un usuario existente por su ID, incluyendo su rol de cliente."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario y rol de cliente actualizados con exito."),
            @ApiResponse(responseCode = "404", description = "Tenant, cliente o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PutMapping("/{userId}")
    public ResponseEntity<Void> updateUser(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @RequestParam(required = true) String clientId,
            @Parameter(description = "El ID del usuario a actualizar.")
            @PathVariable UUID userId,
            @RequestBody UserRequest updatedUser) {
        log.info("Solicitud para actualizar el usuario con ID '{}' del tenant: {} y cliente: {}", userId, realm, clientId);
        userClientService.updateUser(realm, clientId, userId.toString(), updatedUser);
        return ResponseEntity.ok().build();
    }

    /**
     * Endpoint para eliminar un usuario por su ID.
     *
     * @param realm  El nombre del realm (tenant).
     * @param userId El ID del usuario a eliminar.
     * @return Una {@link ResponseEntity} vacía con estado NO_CONTENT.
     */
    @Operation(
            summary = "Elimina un usuario",
            description = "Elimina un usuario de un realm por su ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Usuario eliminado con exito."),
            @ApiResponse(responseCode = "404", description = "Tenant o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del usuario a eliminar.")
            @PathVariable UUID userId) {
        log.info("Solicitud para eliminar el usuario con ID '{}' del tenant: {}", userId, realm);
        userService.deleteUser(realm, userId.toString());
        return ResponseEntity.noContent().build();
    }

    /**
     * Endpoint para obtener un usuario por ID junto con sus roles de cliente.
     *
     * @param realm    El nombre del realm (tenant).
     * @param clientId El ID del cliente.
     * @param userId   El ID del usuario en formato UUID.
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
    public ResponseEntity<UserWithRoles> getUserById(
            @Parameter(description = "El nombre del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @RequestParam(required = true) String clientId,
            @Parameter(description = "El ID del usuario a obtener.")
            @PathVariable UUID userId) {
        log.info("Iniciando solicitud para obtener el usuario con ID '{}' del cliente '{}' en el tenant '{}'.", userId, clientId, realm);
        UserWithRoles userDetails = userClientService.getUserByIdWithClientRoles(realm, clientId, userId.toString());
        log.info("Usuario con ID '{}' y roles de cliente recuperados exitosamente del cliente '{}'.", userId, clientId);
        return ResponseEntity.ok(userDetails);
    }

    /**
     * Endpoint para obtener un usuario por su email y sus roles de cliente.
     *
     * @param realm    El nombre del realm (tenant).
     * @param clientId El ID del cliente.
     * @param email    El correo electrónico del usuario a buscar.
     * @return Una {@link ResponseEntity} con el objeto {@link UserWithRoles}.
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
    public ResponseEntity<UserWithRoles> getUserByEmail(
            @Parameter(description = "El nombre del realm.")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente.")
            @RequestParam(required = true) String clientId,
            @Parameter(description = "El email del usuario a obtener.")
            @PathVariable String email) {
        log.info("Iniciando solicitud para obtener el usuario con el email '{}' del cliente '{}' en el realm '{}'.", email, clientId, realm);
        UserWithRoles userDetails = userClientService.getUserByEmailWithClientRoles(realm, clientId, email);
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

    /**
     * Endpoint para restablecer la contraseña de un usuario.
     * <p>
     * Este método no cambia, ya que el restablecimiento de contraseña es una
     * operación de nivel de usuario, no de rol de cliente.
     *
     * @param realm       El nombre del realm (tenant).
     * @param userId      El ID del usuario en formato UUID.
     * @param newPassword La nueva contraseña en formato de texto.
     * @return Una {@link ResponseEntity} con estado NO_CONTENT si el restablecimiento fue exitoso.
     */
    @Operation(
            summary = "Restablece la contrasena de un usuario",
            description = "Cambia la contrasena de un usuario existente por una nueva."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Contrasena restablecida con exito."),
            @ApiResponse(responseCode = "400", description = "Datos de entrada invalidos.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o usuario no encontrado.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/{userId}/password-reset")
    public ResponseEntity<Void> resetUserPassword(
            @Parameter(description = "El nombre del realm.")
            @PathVariable String realm,
            @Parameter(description = "El ID del usuario a actualizar")
            @PathVariable UUID userId,
            @RequestBody PasswordRequest newPassword) {
        log.info("Solicitud para restablecer la password del usuario con ID '{}' en el realm: {}", userId, realm);
        userService.resetUserPassword(realm, userId.toString(), newPassword.newPassword());
        return ResponseEntity.noContent().build();
    }
}