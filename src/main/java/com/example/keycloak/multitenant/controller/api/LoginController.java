package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.model.token.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.LoginService;
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
 * Controlador REST para gestionar el login de usuarios.
 * <p>
 * Este controlador maneja el proceso de autenticación manual de usuarios contra Keycloak
 * utilizando el flujo de Password Grant Type, e integra la autenticación con Spring Security.
 * También gestiona las operaciones de renovación de tokens y cierre de sesión.
 * Está diseñado para ser multi-tenant, adaptándose al {@code realm} proporcionado en la URL.
 *
 * @author Angel Fm
 * @version 1.0
 * @see LoginService
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Authentication", description = "Operaciones de autenticacion y gestion de sesion")
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final KeycloakProperties keycloakProperties;
    private final LoginService loginService;

    /**
     * Constructor para la inyeccion de dependencias de Spring.
     *
     * @param authenticationManager     Gestor de autenticacion de Spring Security.
     * @param securityContextRepository Repositorio para guardar el contexto de seguridad en la sesion.
     * @param loginService              Servicio para manejar la logica de autenticacion con Keycloak.
     * @param keycloakProperties        Propiedades de configuracion de Keycloak.
     */
    public LoginController(AuthenticationManager authenticationManager,
                           SecurityContextRepository securityContextRepository,
                           LoginService loginService,
                           KeycloakProperties keycloakProperties) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.keycloakProperties = keycloakProperties;
        this.loginService = loginService;
        log.info("LoginController inicializado.");
    }

    /**
     * Maneja la solicitud POST de login de un usuario para un tenant específico.
     * <p>
     * Este método delega la autenticación a {@link LoginService} y, si es exitosa,
     * integra la autenticación con Spring Security para establecer la sesión.
     *
     * @param realm    El nombre del realm (tenant) para el que se intenta el login.
     * @param client   El nombre del cliente del realm.
     * @param username El nombre de usuario proporcionado en el formulario de login.
     * @param password La contraseña proporcionada en el formulario de login.
     * @param request  La solicitud HTTP.
     * @param response La respuesta HTTP.
     * @return Un {@link ResponseEntity} con los tokens y la información del usuario.
     */
    @Operation(
            summary = "Autentica un usuario y crea una sesion.",
            description = "Delega la autenticacion a Keycloak y, si es exitosa, establece una sesion de Spring Security."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login exitoso, se devuelven los tokens y la informacion del usuario.",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
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

        LoginResponse loginResponse = loginService.authenticate(realm, client, username, password);

        log.debug("Integrando autenticación con Spring Security");
        UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                loginResponse.getPreferredUsername(), SecurityConfig.DUMMY_PASSWORD,
                loginResponse.getRoles().stream().map(SimpleGrantedAuthority::new).toList()
        );
        Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);
        log.debug("Usuario '{}' autenticado por AuthenticationManager de Spring Security.", loginResponse.getPreferredUsername());

        SecurityContextHolder.getContext().setAuthentication(authenticatedResult);
        SecurityContext sc = SecurityContextHolder.getContext();
        securityContextRepository.saveContext(sc, request, response);
        log.debug("SecurityContext guardado en la sesion HTTP para el usuario '{}'.", loginResponse.getPreferredUsername());

        //Guardamos realm y client en sesion (se usa para logoutSuccessHandler y refresh)
        //El refresh token no se guarda porque lo gestiona backend go
        HttpSession session = request.getSession(true);
        session.setAttribute("realm", realm);
        session.setAttribute("client", client);
        log.debug("Realm '{}' y client '{}' guardados en la sesión.", realm, client);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("message", "Login successful");
        responseBody.put("username", loginResponse.getUsername());
        responseBody.put("email", loginResponse.getEmail());
        responseBody.put("fullName", loginResponse.getFullName());
        responseBody.put("roles", loginResponse.getRoles());
        responseBody.put("access_token", loginResponse.getAccessToken());
        responseBody.put("idToken", loginResponse.getIdToken());
        responseBody.put("refresh_token", loginResponse.getRefreshToken());
        responseBody.put("expiresIn", loginResponse.getExpiresIn());
        responseBody.put("refreshExpiresIn", loginResponse.getRefreshExpiresIn());
        responseBody.put("realm", loginResponse.getRealm());
        responseBody.put("client", loginResponse.getClient());

        log.info("Login exitoso para el usuario '{}'.", loginResponse.getPreferredUsername());
        return ResponseEntity.ok(responseBody);
    }

    /**
     * Maneja la solicitud POST para renovar un token de acceso utilizando un refresh token.
     * <p>
     * Se espera que el refresh token, realm y client estén en el cuerpo JSON de la solicitud.
     * Este método utiliza la información de la sesión HTTP para contextualizar la petición.
     *
     * @param request La solicitud HTTP.
     * @param token   Objeto que contiene el refresh token.
     * @return Un {@link ResponseEntity} con el nuevo access token y refresh token.
     * @throws ResponseStatusException si el refresh token, realm o client no son válidos.
     */
    @Operation(
            summary = "Renueva el token de acceso usando un refresh token.",
            description = "Delega la renovacion del token a Keycloak. Espera un refresh token en el cuerpo de la peticion."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Renovacion de token exitosa.",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
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

        LoginResponse loginResponse = loginService.refreshToken(token.refreshToken(), realm, client);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("message", "Token refreshed successfully");
        responseBody.put("access_token", loginResponse.getAccessToken());
        responseBody.put("idToken", loginResponse.getIdToken());
        responseBody.put("refresh_token", loginResponse.getRefreshToken());
        responseBody.put("expiresIn", loginResponse.getExpiresIn());
        responseBody.put("refreshExpiresIn", loginResponse.getRefreshExpiresIn());
        responseBody.put("realm", loginResponse.getRealm());
        responseBody.put("client", loginResponse.getClient());

        log.info("Token de acceso renovado exitosamente.");
        return ResponseEntity.ok(responseBody);
    }

    /**
     * Maneja la solicitud POST para cerrar la sesión de un usuario.
     * <p>
     * Este metodo revoca el refresh token en Keycloak para invalidar la sesión
     * y simultáneamente invalida la sesión HTTP local de Spring Security.
     *
     * @param request La solicitud HTTP, necesaria para obtener la sesión actual.
     * @param token   El objeto {@link RefreshTokenRequest} que contiene el refresh token a revocar.
     * @return Un {@link ResponseEntity} con un mensaje de éxito.
     * @throws ResponseStatusException Si el refresh token, realm o client no son válidos.
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

        loginService.revokeRefreshToken(token.refreshToken(), realm, client);
        session.invalidate();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Logout exitoso. Token revocado.");
        return ResponseEntity.ok(response);
    }
}