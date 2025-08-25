package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.AuthResponse;
import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;


/**
 * Controlador para gestionar el proceso de login manual de usuarios contra Keycloak
 * utilizando el flujo de Password Grant Type, e integrando la autenticación con Spring Security.
 * También maneja las redirecciones en caso de éxito o error en el proceso de autenticación.
 * Este controlador está diseñado para ser multi-tenant, adaptándose al 'realm' proporcionado en la URL.
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Authentication", description = "Operaciones de autenticacion y gestion de sesion")
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final KeycloakProperties keycloakProperties;
    private final AuthService authService;

    /**
     * Constructor para la inyeccion de dependencias de Spring.
     *
     * @param authenticationManager     Gestor de autenticacion de Spring Security.
     * @param securityContextRepository Repositorio para guardar el contexto de seguridad en la sesion.
     * @param authService               Servicio para manejar la logica de autenticacion con Keycloak.
     * @param keycloakProperties        Propiedades de configuracion de Keycloak.
     */
    public LoginController(AuthenticationManager authenticationManager,
                           SecurityContextRepository securityContextRepository,
                           AuthService authService,
                           KeycloakProperties keycloakProperties) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.keycloakProperties = keycloakProperties;
        this.authService = authService;
        log.info("LoginController inicializado.");
    }

    /**
     * Maneja la solicitud POST de login de un usuario para un tenant específico.
     * Este método delega la autenticación a {@link AuthService} y, si es exitosa,
     * integra la autenticación con Spring Security para establecer la sesión.
     * El refresh token se devuelve en el cuerpo JSON a Go.
     *
     * @param realm    El nombre del realm (tenant) para el que se intenta el login.
     * @param client   El nombre de clientId es el cliente del realm.
     * @param username El nombre de usuario proporcionado en el formulario de login.
     * @param password La contraseña proporcionada en el formulario de login (real, para Keycloak).
     * @param request  La solicitud HTTP.
     * @param response La respuesta HTTP.
     * @return Un {@link ResponseEntity} con los tokens de acceso, refresh y la información del usuario.
     */
    @Operation(
            summary = "Autentica un usuario y crea una sesion.",
            description = "Delega la autenticacion a Keycloak y, si es exitosa, establece una sesion de Spring Security."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login exitoso, se devuelven los tokens y la informacion del usuario.",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Credenciales invalidas o datos de sesion faltantes.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Tenant o cliente no reconocido.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/{realm}/{client}/do_login")
    public ResponseEntity<Map<String, Object>> doLogin(
            @Parameter(description = "El identificador del tenant (realm).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Keycloak.", required = true)
            @PathVariable String client,
            @Parameter(description = "El nombre de usuario para el login.", required = true)
            @RequestParam String username,
            @Parameter(description = "La contraseña del usuario.", required = true)
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        log.info("Intento de login para usuario '{}' en tenant '{}' con cliente keycloak '{}'", username, realm, client);

        AuthResponse authResponse = authService.authenticate(realm, client, username, password);

        log.debug("Integrando autenticación con Spring Security");
        UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                authResponse.getPreferredUsername(), SecurityConfig.DUMMY_PASSWORD,
                authResponse.getRoles().stream().map(SimpleGrantedAuthority::new).toList()
        );
        Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);
        log.debug("Usuario '{}' autenticado por AuthenticationManager de Spring Security.", authResponse.getPreferredUsername());

        SecurityContextHolder.getContext().setAuthentication(authenticatedResult);
        SecurityContext sc = SecurityContextHolder.getContext();
        securityContextRepository.saveContext(sc, request, response);
        log.debug("SecurityContext guardado en la sesion HTTP para el usuario '{}'.", authResponse.getPreferredUsername());

        //Guardamos realm y client en sesion (se usa para logoutSuccessHandler y refresh)
        //El refresh token no se guarda porque lo gestiona backend go
        HttpSession session = request.getSession(true);
        session.setAttribute("realm", realm);
        session.setAttribute("client", client);
        log.debug("Realm '{}' y client '{}' guardados en la sesión.", realm, client);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("message", "Login successful");
        responseBody.put("username", authResponse.getUsername());
        responseBody.put("email", authResponse.getEmail());
        responseBody.put("fullName", authResponse.getFullName());
        responseBody.put("roles", authResponse.getRoles());
        responseBody.put("access_token", authResponse.getAccessToken());
        responseBody.put("idToken", authResponse.getIdToken());
        responseBody.put("refresh_token", authResponse.getRefreshToken());
        responseBody.put("expiresIn", authResponse.getExpiresIn());
        responseBody.put("refreshExpiresIn", authResponse.getRefreshExpiresIn());
        responseBody.put("realm", authResponse.getRealm());
        responseBody.put("client", authResponse.getClient());

        log.info("Login exitoso para el usuario '{}'.", authResponse.getPreferredUsername());
        return ResponseEntity.ok(responseBody);
    }

    /**
     * Maneja la solicitud POST para renovar un token de acceso utilizando un refresh token.
     * El refresh token, realm y client se esperan en el cuerpo JSON de la solicitud de Go.
     *
     * @param token Objeto que contiene el refresh token.
     * @return Un {@link ResponseEntity} con el nuevo access token, id token y refresh token.
     */
    @Operation(
            summary = "Renueva el token de acceso usando un refresh token.",
            description = "Delega la renovacion del token a Keycloak. Espera un refresh token en el cuerpo de la peticion."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Renovacion de token exitosa.",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Refresh token no valido o datos de sesion faltantes.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Sesion no activa.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(HttpServletRequest request, @RequestBody RefreshTokenRequest token) {
        log.info("Intento de refresh token");

        if (token.refreshToken() == null || token.refreshToken().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El campo refresh_token es obnligatorio.");
        }

        HttpSession session = request.getSession(false);
        if (session == null) {
            log.warn("No hay sesion activa al intetnar refrescar token.");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No existe session activa.");
        }

        String realm = (String) session.getAttribute("realm");
        String client = (String) session.getAttribute("client");

        if (realm == null || client == null) {
            log.warn("No se encontraron realm o client en la sesion");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Faltan datos de sesion: 'realm' o 'client'.");
        }

        AuthResponse authResponse = authService.refreshToken(token.refreshToken(), realm, client);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("message", "Token refreshed successfully");
        responseBody.put("access_token", authResponse.getAccessToken());
        responseBody.put("idToken", authResponse.getIdToken());
        responseBody.put("refresh_token", authResponse.getRefreshToken());
        responseBody.put("expiresIn", authResponse.getExpiresIn());
        responseBody.put("refreshExpiresIn", authResponse.getRefreshExpiresIn());
        responseBody.put("realm", authResponse.getRealm());
        responseBody.put("client", authResponse.getClient());

        log.info("Token de acceso renovado exitosamente.");
        return ResponseEntity.ok(responseBody);
    }

    /**
     * Maneja la solicitud POST para cerrar la sesión de un usuario.
     * Este metodo revoca el refresh token en Keycloak para invalidar la sesión
     * y simultáneamente invalida la sesión HTTP local de Spring Security.
     *
     * @param request La solicitud HTTP, necesaria para obtener la sesión actual.
     * @param token   El objeto {@link RefreshTokenRequest} que contiene el refresh token a revocar.
     * @return Un {@link ResponseEntity} con un mensaje de éxito.
     * @throws ResponseStatusException Si el refresh token es nulo o vacío (HTTP 400),
     *                                 si no hay una sesión HTTP activa (HTTP 401),
     *                                 o si faltan los datos del realm y client en la sesión (HTTP 400).
     */
    @Operation(
            summary = "Revoca el refresh token y cierra la sesion del usuario.",
            description = "Invalida el refresh token en Keycloak y la sesion de Spring Security."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Logout exitoso, token revocado.",
                    content = @Content(schema = @Schema(implementation = Map.class))),
            @ApiResponse(responseCode = "400", description = "Refresh token no valido o datos de sesion faltantes.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Sesion no activa.",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request, @RequestBody RefreshTokenRequest token) {
        log.info("Intento de logout...");

        if (token.refreshToken() == null || token.refreshToken().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El campo 'refresh_token' es obligatorio.");
        }

        HttpSession session = request.getSession(false);
        if (session == null) {
            log.warn("No hay sesion activa al intentar logout.");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No existe sesion activa.");
        }

        String realm = (String) session.getAttribute("realm");
        String client = (String) session.getAttribute("client");

        if (realm == null || client == null) {
            log.warn("No se encontraron realm o client en la sesion");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Faltan datos de sesion: 'realm' o 'client'.");
        }

        authService.revokeRefreshToken(token.refreshToken(), realm, client);
        session.invalidate();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Logout exitoso. Token revocado.");
        return ResponseEntity.ok(response);
    }
}