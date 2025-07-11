package com.example.keycloakdemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.keycloakdemo.config.KeycloakProperties;
import com.example.keycloakdemo.config.SecurityConfig;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
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
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

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
    private final WebClient webClient;
    private final KeycloakProperties keycloakProperties;

    /**
     * Constructor para la inyección de dependencias de Spring.
     *
     * @param authenticationManager           Instancia de {@link AuthenticationManager}.
     * @param securityContextRepository       Instancia de {@link SecurityContextRepository}.
     */
    public LoginController(AuthenticationManager authenticationManager,
                           SecurityContextRepository securityContextRepository,
                           WebClient.Builder webClientBuilder,
                           KeycloakProperties keycloakProperties) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.webClient = webClientBuilder.build();
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
        response.put("realm", realm); // Añade el ID del tenant al modelo.
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

        String clientSecret = keycloakProperties.getClientSecrets().get(client);

        if (clientSecret == null) {
            log.warn("Client Secret no encontrado para el Client ID: {}", client);
            throw new IllegalArgumentException("Client ID configurado pero secreto no encontrado para: " + client + "." +
                    "Asegurate de que el client ID esté configurado en 'keycloak.client-secrets' en properties.");
        }
        log.debug("Client Secret encontrado para Client ID: {}", client);

        // Construye la URL del endpoint de tokens de Keycloak para el realm específico.
        String tokenUrl = keycloakProperties.getAuthServerUrl() + "/realms/" + keycloakProperties.getSingleRealmName() + "/protocol/openid-connect/token";
        log.debug("URL de token de Keycloak: {}", tokenUrl);

        // Prepara los parámetros para la solicitud POST al endpoint de tokens de Keycloak (Password Grant).
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", client);
        params.add("username", username);
        params.add("password", password);
        params.add("scope", "openid");
        log.debug("Parametros de solicitud de token: {}", params);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Prepara la autenticación básica para el cliente (Client ID:Client Secret).
        String clientAuth = client + ":" + clientSecret; // <--- USA EL CLIENT SECRET DINÁMICO
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);
        log.debug("Cabeceras de autenticación preparados.");

        // Realiza la solicitud POST a Keycloak para obtener el token.
        String tokenResponse = webClient.post()
                .uri(tokenUrl)
                .headers(httpHeaders -> httpHeaders.addAll(headers))
                .body(BodyInserters.fromFormData(params))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        log.info("Respuesta exitosa de Keycloak para el usuario '{}'", username);
        JsonNode node = objectMapper.readTree(tokenResponse);

        String accessToken = node.get("access_token").asText();
        String idToken = node.has("id_token") ? node.get("id_token").asText() : null;
        String refreshToken = node.has("refresh_token") ? node.get("refresh_token").asText() : null;
        long expiresIn = node.has("expires_in") ? node.get("expires_in").asLong() : 0;
        long refreshExpiresIn = node.has("refresh_expires_in") ? node.get("refresh_expires_in").asLong() : 0;

        //Decodificador el Id token para obtener los claims ( atributos )
        DecodedJWT decodeIdToken = null;
        if (idToken != null) {
            decodeIdToken = JWT.decode(idToken);
            log.debug("ID Token decodificado.");
        }else {
            log.warn("No se recibió ID Token de Keycloak para el usuario '{}'.", username);
        }

        List<SimpleGrantedAuthority> extractedAuthorities = new ArrayList<>();
        String email = null;
        String fullName = null;
        String preferredUsername = username;

        if (decodeIdToken != null) {
            // Extrae roles a nivel de Realm.
            Map<String, Object> realmAccess = decodeIdToken.getClaim("realm_access").asMap();
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> realmRoles = (List<String>) realmAccess.get("roles");
                if (realmRoles != null) {
                    realmRoles.forEach(role -> extractedAuthorities.add(
                            new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
                    log.debug("Roles de realm extraidos: {}", realmRoles);
                }
            }
            // Extrae roles a nivel de Cliente (Resource Access).
            Map<String, Object> resourceAccess = decodeIdToken.getClaim("resource_access").asMap();
            if (resourceAccess != null && resourceAccess.containsKey(client)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(client);
                if (clientAccess != null && clientAccess.containsKey("roles")) {
                    @SuppressWarnings("unchecked")
                    List<String> clientRoles = (List<String>) clientAccess.get("roles");
                    if (clientRoles != null) {
                        clientRoles.forEach(role-> extractedAuthorities.add(
                                new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
                        log.debug("Roles de cliente '{}' extraidos: {}", client, clientRoles);
                    }
                }
            }
            // Extrae otros claims del token si están disponibles.
            email = decodeIdToken.getClaim("email") != null ? decodeIdToken.getClaim("email").asString() : null;
            fullName = decodeIdToken.getClaim("name") != null ? decodeIdToken.getClaim("name").asString() : null;
            preferredUsername = decodeIdToken.getClaim("preferred_username") != null ? decodeIdToken.getClaim("preferred_username").asString() : username;
            log.debug("Claims de usuario extraidos: email={}, fullName={}, preferredUsername={}", email, fullName, preferredUsername);

        } else if (accessToken != null){
            //Si no hay ID Token, intentar decodificar el Access Token para obtener algunos claims basicos
            DecodedJWT decodedAccessToken = JWT.decode(accessToken);
            email = decodedAccessToken.getClaim("email") != null ? decodedAccessToken.getClaim("email").asString() : null;
            fullName = decodedAccessToken.getClaim("name") != null ? decodedAccessToken.getClaim("name").asString() : null;
            preferredUsername = decodedAccessToken.getClaim("preferred_username") != null ? decodedAccessToken.getClaim("preferred_username").asString() : username;
            log.warn("ID Token no disponible. Extrayendo claims de Access Token: email={}, fullName={}, preferredUsername={}", email, fullName, preferredUsername);

            Map<String, Object> realmAccess = decodedAccessToken.getClaim("realm_access").asMap();
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> realmRoles = (List<String>) realmAccess.get("roles");
                if (realmRoles != null) {
                    realmRoles.forEach(role -> extractedAuthorities.add(
                            new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
                    log.debug("Roles de realm extraidos: {}", realmRoles);
                }
            }
        }

        // --- INICIO DE INTEGRACIÓN CON SPRING SECURITY ---
        log.debug("Integrando autenticación con Spring Security");

        // 1. Crear un UsernamePasswordAuthenticationToken INAUTENTICADO. TODO mirar como integrar el password correctamente sin hardcodeado
        UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                preferredUsername, SecurityConfig.DUMMY_PASSWORD
        );

        // 2. Delegar la autenticación al AuthenticationManager de Spring Security.
        Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);
        log.debug("Usuario '{}' autenticado por AuthenticationManager de Spring Security.", preferredUsername);

        // 3. Crear un NUEVO AuthenticationToken FINAL con el principal autenticado y los roles REALES.
        Authentication finalAuthentication = new UsernamePasswordAuthenticationToken(
                authenticatedResult.getPrincipal(),
                authenticatedResult.getCredentials(),
                extractedAuthorities
        );

        // 4. Establecer el objeto Authentication FINAL en el SecurityContextHolder.
        SecurityContextHolder.getContext().setAuthentication(finalAuthentication);
        log.debug("SecurityContextHolder actualizado con la autenticación final.");

        // 5. Guardar explícitamente el SecurityContext en el repositorio de contexto de seguridad.
        SecurityContext sc = SecurityContextHolder.getContext();
        securityContextRepository.saveContext(sc, request, response);
        log.debug("SecurityContext guardado en la sesión HTTP para el usuario '{}'.", preferredUsername);

        // --- FIN DE INTEGRACIÓN CON SPRING SECURITY ---

        //Respuesta Json para frontend
        responseBody.put("message", "Login successful");
        responseBody.put("username", preferredUsername);
        responseBody.put("email", email);
        responseBody.put("fullName", fullName);
        responseBody.put("roles", extractedAuthorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
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
