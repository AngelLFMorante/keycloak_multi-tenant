package com.example.keycloakdemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
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
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
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

    @Value("${keycloak.auth-server-url}")
    private String keycloakBaseUrl;

    /**
     * El nombre del unico realm de keycloak que se utiizara para todas las operaciones.
     */
    @Value("${keycloak.single-realm-name}")
    private String singleKeycloakRealm;

    /**
     * Mapeo de Client IDs a Client Secrets.
     * La clave es el client id ( del realm ) y el valor es su client secret
     * Se inyecta desde las propiedades de la aplicación
     */
    @Value("#{${keycloak.client-secrets}}") //inyeccion de un mapa de propiedades
    private Map<String,String> clientSecrets;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final WebClient webClient;

    /**
     * Constructor para la inyección de dependencias de Spring.
     *
     * @param authenticationManager           Instancia de {@link AuthenticationManager}.
     * @param securityContextRepository       Instancia de {@link SecurityContextRepository}.
     */
    public LoginController(AuthenticationManager authenticationManager,
                           SecurityContextRepository securityContextRepository,
                           WebClient.Builder webClientBuilder) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.webClient = webClientBuilder.build();

    }

    /**
     * Maneja la solicitud POST de login de un usuario para un tenant específico.
     * Este método realiza la autenticación contra Keycloak y, si es exitosa,
     * integra la autenticación con Spring Security para establecer la sesión.
     * En caso de error, redirige al usuario a la página de login con un mensaje.
     *
     * @param realm      El nombre del realm (tenant) para el que se intenta el login.
     * @param clientId   El nombre de clientId es el cliente del realm.
     * @param username   El nombre de usuario proporcionado en el formulario de login.
     * @param password   La contraseña proporcionada en el formulario de login (real, para Keycloak).
     * @param request    La solicitud HTTP.
     * @param response   La respuesta HTTP, utilizada para redirecciones en caso de error.
     * @throws IOException Si ocurre un error de E/S durante la comunicación HTTP o la redirección.
     */
    @PostMapping("/{realm}/{client}/do_login")
    public ResponseEntity<Map<String, Object>> doLogin(
            @PathVariable String realm,
            @PathVariable String clientId,
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        Map<String, Object> responseBody = new HashMap<>();

        String clientSecret = clientSecrets.get(clientId);

        if (clientSecret == null) {
            responseBody.put("error", "Tenant no configurado.");
            responseBody.put("tenantId", realm);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseBody);
        }

        // Construye la URL del endpoint de tokens de Keycloak para el realm específico.
        String tokenUrl = keycloakBaseUrl + "/realms/" + singleKeycloakRealm + "/protocol/openid-connect/token";

        // Prepara los parámetros para la solicitud POST al endpoint de tokens de Keycloak (Password Grant).
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", clientId);
        params.add("username", username);
        params.add("password", password);
        params.add("scope", "openid");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Prepara la autenticación básica para el cliente (Client ID:Client Secret).
        String clientAuth = clientId + ":" + clientSecret; // <--- USA EL CLIENT SECRET DINÁMICO
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);


        try {
            // Realiza la solicitud POST a Keycloak para obtener el token.
            String tokenResponse = webClient.post()
                    .uri(tokenUrl)
                    .headers(httpHeaders -> httpHeaders.addAll(headers))
                    .body(BodyInserters.fromFormData(params))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

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
                        for (String role : realmRoles) {
                            extractedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                        }
                    }
                }
                // Extrae roles a nivel de Cliente (Resource Access).
                Map<String, Object> resourceAccess = decodeIdToken.getClaim("resource_access").asMap();
                if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
                    if (clientAccess != null && clientAccess.containsKey("roles")) {
                        @SuppressWarnings("unchecked")
                        List<String> clientRoles = (List<String>) clientAccess.get("roles");
                        if (clientRoles != null) {
                            for (String role : clientRoles) {
                                extractedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                            }
                        }
                    }
                }
                // Extrae otros claims del token si están disponibles.
                if (decodeIdToken.getClaim("email") != null) {
                    email = decodeIdToken.getClaim("email").asString();
                }
                if (decodeIdToken.getClaim("name") != null) {
                    fullName = decodeIdToken.getClaim("name").asString();
                }
                if (decodeIdToken.getClaim("preferred_username") != null) {
                    preferredUsername = decodeIdToken.getClaim("preferred_username").asString();
                }
            } else {
                System.err.println("Advertencia: Access Token es nulo en una respuesta exitosa de Keycloak.");

            }
            // --- INICIO DE INTEGRACIÓN CON SPRING SECURITY ---

            // 1. Crear un UsernamePasswordAuthenticationToken INAUTENTICADO.
            UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                    preferredUsername, SecurityConfig.DUMMY_PASSWORD
            );

            // 2. Delegar la autenticación al AuthenticationManager de Spring Security.
            Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);

            // 3. Crear un NUEVO AuthenticationToken FINAL con el principal autenticado y los roles REALES.
            Authentication finalAuthentication = new UsernamePasswordAuthenticationToken(
                    authenticatedResult.getPrincipal(),
                    authenticatedResult.getCredentials(),
                    extractedAuthorities
            );

            // 4. Establecer el objeto Authentication FINAL en el SecurityContextHolder.
            SecurityContextHolder.getContext().setAuthentication(finalAuthentication);

            // 5. Guardar explícitamente el SecurityContext en el repositorio de contexto de seguridad.
            SecurityContext sc = SecurityContextHolder.getContext();
            securityContextRepository.saveContext(sc, request, response);

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
            responseBody.put("experisIn", expiresIn);
            responseBody.put("refreshExpiresIn", refreshExpiresIn);
            responseBody.put("realm", realm);
            responseBody.put("client", clientId);

            return ResponseEntity.ok(responseBody);

        } catch (HttpClientErrorException.Unauthorized e) {
            responseBody.put("error", "Error de autenticación: Usuario o cliente no autorizado con Keycloak.");
            responseBody.put("tenantId", realm);
            System.err.println("Error 401 Unauthorized de Keycloak: " + e.getResponseBodyAsString());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
        } catch (Exception e) {
            responseBody.put("error", "Error en la autenticación: " + (e.getMessage() != null ? e.getMessage() : "Error desconocido. Revisa logs."));
            responseBody.put("tenantId", realm);
            System.err.println("Excepción general al autenticar: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}
