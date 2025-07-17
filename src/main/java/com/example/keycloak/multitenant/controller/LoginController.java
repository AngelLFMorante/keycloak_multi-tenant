package com.example.keycloak.multitenant.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.config.SecurityConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;


/**
 * Controlador para gestionar el proceso de login manual de usuarios contra Keycloak
 * utilizando el flujo de Password Grant Type, e integrando la autenticación con Spring Security.
 * También maneja las redirecciones en caso de éxito o error en el proceso de autenticación.
 * Este controlador está diseñado para ser multi-tenant, adaptándose al 'realm' proporcionado en la URL.
 */
@RestController
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final RestTemplate restTemplate;
    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor para la inyección de dependencias de Spring.
     * @param authenticationManager
     * @param securityContextRepository
     * @param restTemplate
     * @param keycloakProperties
     */
    public LoginController(AuthenticationManager authenticationManager,
                           SecurityContextRepository securityContextRepository,
                           RestTemplate restTemplate,
                           KeycloakProperties keycloakProperties) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.restTemplate = restTemplate;
        this.keycloakProperties = keycloakProperties;
        log.info("LoginController inicializado.");
    }

    /**
     * Maneja la solicitud GET para la página de login específica de un tenant.
     * Añade el ID del tenant al modelo.
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
     * Este método realiza la autenticación contra Keycloak y, si es exitosa,
     * integra la autenticación con Spring Security para establecer la sesión.
     * En caso de error, redirige al usuario a la página de login con un mensaje.
     *
     * @param realm      El nombre del realm (tenant) para el que se intenta el login.
     * @param client   El nombre de clientId es el cliente del realm.
     * @param username   El nombre de usuario proporcionado en el formulario de login.
     * @param password   La contraseña proporcionada en el formulario de login (real, para Keycloak).
     * @param request    La solicitud HTTP.
     * @param response   La respuesta HTTP, utilizada para redirecciones en caso de error.
     * @throws IOException Si ocurre un error de E/S durante la comunicación HTTP o la redirección.
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

        Map<String, Object> responseBody = new HashMap<>();

        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo de realm no encontrado para el tenantPath: {}", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant " + realm + " no reconocido.");
        }
        log.debug("Tenant '{}' mapeado al realm de Keycloak: '{}'", realm, keycloakRealm);

        String clientSecret = keycloakProperties.getClientSecrets().get(client);
        if (clientSecret == null) {
            log.warn("Client Secret no encontrado para el Client ID: {}", client);
            throw new IllegalArgumentException("Client ID configurado pero secreto no encontrado para: " + client + "." +
                    "Asegurate de que el client ID esté configurado en 'keycloak.client-secrets' en properties.");
        }
        log.debug("Client Secret encontrado para Client ID: {}", client);

        // Construye la URL del endpoint de tokens de Keycloak para el realm específico.
        String tokenUrl = keycloakProperties.getAuthServerUrl() + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";
        log.debug("URL de token de Keycloak: {}", tokenUrl);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", client);
        params.add("username", username);
        params.add("password", password);
        params.add("scope", "openid profile email");
        log.debug("Parametros de solicitud de token: {}", params);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String clientAuth = client + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);
        log.debug("Cabeceras de autenticación preparados.");

        ResponseEntity<String> tokenResponseEntity = restTemplate.postForEntity(
                tokenUrl,
                new HttpEntity<>(params, headers),
                String.class
        );

        String tokenResponse = tokenResponseEntity.getBody();
        log.info("Respuesta exitosa de Keycloak para el usuario '{}'", username);

        JsonNode node = objectMapper.readTree(tokenResponse);

        String accessToken = node.get("access_token").asText();
        String idToken = node.has("id_token") ? node.get("id_token").asText() : null;
        String refreshToken = node.has("refresh_token") ? node.get("refresh_token").asText() : null;
        long expiresIn = node.has("expires_in") ? node.get("expires_in").asLong() : 0;
        long refreshExpiresIn = node.has("refresh_expires_in") ? node.get("refresh_expires_in").asLong() : 0;

        List<SimpleGrantedAuthority> extractedAuthorities = new ArrayList<>();
        String email = null;
        String fullName = null;
        String preferredUsername = username;

        DecodedJWT decodedAccessToken = JWT.decode(accessToken);
        log.debug("Access Token decodificado para extracción de claims y roles.");

        // Extracción de claims del Access Token
        email = decodedAccessToken.getClaim("email") != null ? decodedAccessToken.getClaim("email").asString() : null;
        fullName = decodedAccessToken.getClaim("name") != null ? decodedAccessToken.getClaim("name").asString() : null;
        preferredUsername = decodedAccessToken.getClaim("preferred_username") != null ? decodedAccessToken.getClaim("preferred_username").asString() : username;
        log.debug("Claims de usuario extraidos (desde Access Token): email={}, fullName={}, preferredUsername={}", email, fullName, preferredUsername);

        // Extrae roles a nivel de Realm desde el Access Token.
        Map<String, Object> realmAccess = decodedAccessToken.getClaim("realm_access").asMap();
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            @SuppressWarnings("unchecked")
            List<String> realmRoles = (List<String>) realmAccess.get("roles");
            if (realmRoles != null) {
                realmRoles.forEach(role -> extractedAuthorities.add(
                        new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
                log.debug("Roles de realm extraidos (desde Access Token): {}", realmRoles);
                log.debug("Roles actuales en extractedAuthorities después de roles de realm: {}", extractedAuthorities);
            }
        }

        // Extrae roles a nivel de Cliente (Resource Access) desde el Access Token.
        Map<String, Object> resourceAccess = decodedAccessToken.getClaim("resource_access").asMap();
        if (resourceAccess != null && resourceAccess.containsKey(client)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(client);
            if (clientAccess != null && clientAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> clientRoles = (List<String>) clientAccess.get("roles");
                if (clientRoles != null) {
                    clientRoles.forEach(role -> extractedAuthorities.add(
                            new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
                    log.debug("Roles de cliente '{}' extraidos (desde Access Token): {}", client, clientRoles);
                    log.debug("Roles actuales en extractedAuthorities después de roles de cliente: {}", extractedAuthorities);
                }
            }
        }

        if (idToken != null) {
            DecodedJWT decodedIdToken = JWT.decode(idToken);
            log.debug("ID Token decodificado, pero roles ya extraidos de Access Token. Claims del ID Token: {}", decodedIdToken.getClaims());
        }


        log.debug("Integrando autenticación con Spring Security");
        log.debug("extractedAuthorities antes de pasar a authenticationManager.authenticate: {}", extractedAuthorities);

        UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                preferredUsername, SecurityConfig.DUMMY_PASSWORD, extractedAuthorities
        );
        log.debug("authenticationRequest (con roles) creado: Principal={}, Authorities={}", authenticationRequest.getPrincipal(), authenticationRequest.getAuthorities());

        Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);
        log.debug("Usuario '{}' autenticado por AuthenticationManager de Spring Security.", preferredUsername);
        log.debug("authenticatedResult (desde AuthenticationManager): Principal={}, Authorities={}", authenticatedResult.getPrincipal(), authenticatedResult.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authenticatedResult);
        log.debug("SecurityContextHolder actualizado con la autenticación final. Roles en SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication().getAuthorities());

        SecurityContext sc = SecurityContextHolder.getContext();
        securityContextRepository.saveContext(sc, request, response);
        log.debug("SecurityContext guardado en la sesión HTTP para el usuario '{}'.", preferredUsername);

        responseBody.put("message", "Login successful");
        responseBody.put("username", preferredUsername);
        responseBody.put("email", email);
        responseBody.put("fullName", fullName);
        responseBody.put("roles", extractedAuthorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        log.debug("Roles finales en la respuesta JSON: {}", responseBody.get("roles"));
        responseBody.put("accessToken", accessToken);
        responseBody.put("idToken", idToken);
        responseBody.put("refreshToken", refreshToken);
        responseBody.put("expiresIn", expiresIn);
        responseBody.put("refreshExpiresIn", refreshExpiresIn);
        responseBody.put("realm", realm);
        responseBody.put("client", client);

        log.info("Login exitoso para el usuario '{}'. Devolviendo respuesta JSON.", preferredUsername);
        return ResponseEntity.ok(responseBody);
    }
}