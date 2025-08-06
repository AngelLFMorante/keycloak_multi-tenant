package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.AuthResponse;
import com.example.keycloak.multitenant.model.RefreshTokenRequest;
import com.example.keycloak.multitenant.service.AuthService;
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
import org.springframework.web.bind.annotation.GetMapping;
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
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final KeycloakProperties keycloakProperties;
    private final AuthService authService;

    /**
     * Constructor para la inyección de dependencias de Spring.
     *
     * @param authenticationManager
     * @param securityContextRepository
     * @param authService
     * @param keycloakProperties
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
     * Maneja la solicitud GET para la página de login específica de un tenant.
     * Añade el ID del tenant al modelo.
     *
     * @param realm El nombre del realm (tenant)
     * @return El nombre de la vista
     */
    @GetMapping("/{realm}/login")
    public ResponseEntity<Map<String, Object>> redirectToTenantLogin(@PathVariable String realm) {
        log.info("Solicitud GET para información de registro del tenant: {}", realm);
        Map<String, Object> response = new HashMap<>();
        response.put("realm", realm);

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }

        response.put("keycloakRealm", keycloakRealm);

        return ResponseEntity.ok(response);
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
    @PostMapping("/{realm}/{client}/do_login")
    public ResponseEntity<Map<String, Object>> doLogin(
            @PathVariable String realm,
            @PathVariable String client,
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws Exception {
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

        String realm = session.getAttribute("realm").toString();
        String client = session.getAttribute("client").toString();

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

        String realm = session.getAttribute("realm").toString();
        String client = session.getAttribute("client").toString();

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