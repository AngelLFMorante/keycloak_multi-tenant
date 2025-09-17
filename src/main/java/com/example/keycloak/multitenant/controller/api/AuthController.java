package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.token.ClientCredentialsTokenResponse;
import com.example.keycloak.multitenant.model.ErrorResponse;
import com.example.keycloak.multitenant.model.token.RefreshTokenRequest;
import com.example.keycloak.multitenant.model.token.TokenValidationResponse;
import com.example.keycloak.multitenant.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para manejar operaciones de autenticación y validación de tokens.
 * <p>
 * Esta clase expone endpoints para interactuar con Keycloak, permitiendo la validación
 * de tokens existentes y la obtención de nuevos tokens a través del flujo de
 * "Client Credentials". La lógica de negocio principal se delega a {@link AuthService}.
 *
 * @author Angel Fm
 * @version 1.0
 * @see AuthService
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Autenticación", description = "Endpoints para autenticación y validación de tokens")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param authService El servicio de autenticación para delegar la lógica de negocio.
     */
    public AuthController(AuthService authService) {
        this.authService = authService;
        log.info("AuthController inicializado.");
    }

    /**
     * Valida un token de acceso o de refresco utilizando la API de introspección de Keycloak.
     * <p>
     * El token se envía en el cuerpo de la petición como un objeto JSON. La respuesta indica
     * si el token está activo y, en caso afirmativo, proporciona detalles adicionales
     * extraídos del mismo.
     *
     * @param token  Objeto de solicitud que contiene el token a validar.
     * @param realm  El nombre del realm (tenant) al que pertenece el token.
     * @param client El ID del cliente que solicita la validación del token.
     * @return {@link ResponseEntity} con el objeto de respuesta de validación del token.
     */
    @Operation(
            summary = "Validar token",
            description = "Valida un token mediante Keycloak Introspection. Requiere el token como parámetro de consulta y el realm y client en la ruta."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token válido",
                    content = @Content(schema = @Schema(implementation = TokenValidationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Parámetros de entrada no válidos",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Credenciales incorrectas o token inválido",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o cliente no encontrado",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/{realm}/auth/{client}/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Parameter(description = "Token a validar. Puede ser un access_token o un refresh_token.")
            @RequestBody RefreshTokenRequest token,
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Keycloak.")
            @PathVariable String client) {
        log.info("Solicitud de validación de token para el realm '{}' y cliente '{}'", realm, client);
        TokenValidationResponse response = authService.validateToken(token, realm, client);

        if (response.active()) {
            log.info("Token validado exitosamente para el realm '{}'", realm);
            return ResponseEntity.ok(response);
        } else {
            log.warn("El token proporcionado para el realm '{}' no es válido.", realm);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    /**
     * Endpoint para obtener un token utilizando el flujo de Client Credentials.
     * Este flujo es adecuado para la comunicacion entre servicios (machine-to-machine).
     * El servicio autentica al cliente usando su ID y Secret para obtener un token de acceso.
     *
     * @param realm  El nombre del realm al que pertenece el cliente.
     * @param client El ID del cliente que solicita el token.
     * @return Una respuesta con el token de acceso, su tipo y tiempo de vida.
     */
    @Operation(summary = "Obtener token con Client Credentials",
            description = "Genera un token de acceso para un cliente usando el flujo Client Credentials.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token generado exitosamente",
                    content = @Content(schema = @Schema(implementation = ClientCredentialsTokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Parámetros inválidos",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Autenticación fallida",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error interno",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/{realm}/auth/{client}/token")
    public ResponseEntity<ClientCredentialsTokenResponse> getClientCredentialsToken(
            @Parameter(description = "El identificador del tenant (realm).")
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Keycloak.")
            @PathVariable String client) {
        log.info("Solicitud para obtener token con Client Credentials: realm = {}, client = {}", realm, client);

        ClientCredentialsTokenResponse tokenResponse = authService.getClientCredentialsToken(realm, client);

        log.info("Token de credenciales de cliente obtenido exitosamente para realm = {}, client = {}", realm, client);
        return ResponseEntity.ok(tokenResponse);
    }
}