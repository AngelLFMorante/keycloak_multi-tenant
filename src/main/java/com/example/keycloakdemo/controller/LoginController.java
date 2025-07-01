package com.example.keycloakdemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Importa la configuración de seguridad para acceder a la constante DUMMY_PASSWORD
import com.example.keycloakdemo.config.SecurityConfig;
// Importa el repositorio dinámico de clientes para obtener la información del tenant
import com.example.keycloakdemo.repository.DynamicClientRegistrationRepository;
import com.example.keycloakdemo.model.TenantInfo; // Importa la clase TenantInfo

/**
 * Controlador para gestionar el proceso de login manual de usuarios contra Keycloak
 * utilizando el flujo de Password Grant Type, e integrando la autenticación con Spring Security.
 * También maneja las redirecciones en caso de éxito o error en el proceso de autenticación.
 * Este controlador está diseñado para ser multi-tenant, adaptándose al 'realm' proporcionado en la URL.
 */
@Controller
public class LoginController {

    @Value("${keycloak.auth-server-url}")
    private String keycloakBaseUrl;

    // Eliminamos la inyección del clientSecret directamente desde application.properties,
    // ya que ahora lo obtendremos dinámicamente.
    // @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    // private String clientSecret;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthenticationManager authenticationManager;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final SecurityContextRepository securityContextRepository;
    private final DynamicClientRegistrationRepository dynamicClientRegistrationRepository; // Inyección del repositorio dinámico

    /**
     * Constructor para la inyección de dependencias de Spring.
     *
     * @param authenticationManager           Instancia de {@link AuthenticationManager}.
     * @param authenticationSuccessHandler    Instancia de {@link AuthenticationSuccessHandler}.
     * @param securityContextRepository       Instancia de {@link SecurityContextRepository}.
     * @param dynamicClientRegistrationRepository Instancia de {@link DynamicClientRegistrationRepository}.
     */
    public LoginController(AuthenticationManager authenticationManager,
                           AuthenticationSuccessHandler authenticationSuccessHandler,
                           SecurityContextRepository securityContextRepository,
                           DynamicClientRegistrationRepository dynamicClientRegistrationRepository) {
        this.authenticationManager = authenticationManager;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.securityContextRepository = securityContextRepository;
        this.dynamicClientRegistrationRepository = dynamicClientRegistrationRepository; // Asignación
    }

    /**
     * Maneja la solicitud POST de login de un usuario para un tenant específico.
     * Este método realiza la autenticación contra Keycloak y, si es exitosa,
     * integra la autenticación con Spring Security para establecer la sesión.
     * En caso de error, redirige al usuario a la página de login con un mensaje.
     *
     * @param realm      El nombre del realm (tenant) para el que se intenta el login.
     * @param username   El nombre de usuario proporcionado en el formulario de login.
     * @param password   La contraseña proporcionada en el formulario de login (real, para Keycloak).
     * @param model      El modelo para añadir atributos a la vista (usado para mensajes de error).
     * @param session    La sesión HTTP actual.
     * @param request    La solicitud HTTP.
     * @param response   La respuesta HTTP, utilizada para redirecciones en caso de error.
     * @throws IOException Si ocurre un error de E/S durante la comunicación HTTP o la redirección.
     */
    @PostMapping("/{realm}/do_login")
    public void doLogin(@PathVariable String realm,
                        @RequestParam String username,
                        @RequestParam String password,
                        Model model,
                        HttpSession session,
                        HttpServletRequest request,
                        HttpServletResponse response) throws IOException {

        // Obtener la información del tenant (incluido el clientSecret) de forma dinámica.
        TenantInfo tenantInfo = dynamicClientRegistrationRepository.getTenantMapping().get(realm);

        if (tenantInfo == null) {
            System.err.println("Error: Tenant no encontrado en el mapeo para realm: " + realm);
            model.addAttribute("error", "Tenant no configurado.");
            model.addAttribute("tenantId", realm);
            response.sendRedirect("/login?error=true&tenantId=" + realm);
            return;
        }

        String keycloakRealmName = tenantInfo.realm(); // Nombre del realm en Keycloak (ej. "plexus-realm")
        String clientId = tenantInfo.clientId();       // ID del cliente (ej. "mi-app-plexus")
        String clientSecret = tenantInfo.clientSecret(); // <--- OBTENIDO DINÁMICAMENTE

        // Construye la URL del endpoint de tokens de Keycloak para el realm específico.
        String tokenUrl = keycloakBaseUrl + "/realms/" + keycloakRealmName + "/protocol/openid-connect/token";

        RestTemplate restTemplate = new RestTemplate();

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

        // Crea la entidad de la solicitud HTTP con los parámetros y cabeceras.
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);

        try {
            // Realiza la solicitud POST a Keycloak para obtener el token.
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            // Si la respuesta de Keycloak es exitosa (código 2xx).
            if (tokenResponse.getStatusCode().is2xxSuccessful()) {
                JsonNode node = objectMapper.readTree(tokenResponse.getBody());

                String accessToken = node.get("access_token").asText();
                String idToken = node.has("id_token") ? node.get("id_token").asText() : null;

                session.setAttribute("username", username);

                List<SimpleGrantedAuthority> extractedAuthorities = new ArrayList<>();
                String email = null;
                String fullName = null;
                String preferredUsername = username;

                if (accessToken != null) {
                    DecodedJWT decodedAccessToken = JWT.decode(accessToken);

                    // Extrae roles a nivel de Realm.
                    Map<String, Object> realmAccess = decodedAccessToken.getClaim("realm_access").asMap();
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
                    Map<String, Object> resourceAccess = decodedAccessToken.getClaim("resource_access").asMap();
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
                    if (decodedAccessToken.getClaim("email") != null) {
                        email = decodedAccessToken.getClaim("email").asString();
                    }
                    if (decodedAccessToken.getClaim("name") != null) {
                        fullName = decodedAccessToken.getClaim("name").asString();
                    }
                    if (decodedAccessToken.getClaim("preferred_username") != null) {
                        preferredUsername = decodedAccessToken.getClaim("preferred_username").asString();
                    }
                } else {
                    System.err.println("Advertencia: Access Token es nulo en una respuesta exitosa de Keycloak.");
                    model.addAttribute("error", "Error interno: No se recibió Access Token de Keycloak.");
                    model.addAttribute("tenantId", realm);
                    response.sendRedirect("/login?error=true&tenantId=" + realm);
                    return;
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

                // 6. Invocar el AuthenticationSuccessHandler para manejar la redirección post-login.
                request.setAttribute("tenantIdForRedirect", realm);
                authenticationSuccessHandler.onAuthenticationSuccess(request, response, finalAuthentication);

                // --- FIN DE INTEGRACIÓN CON SPRING SECURITY ---

                // Guardar los datos relevantes del token de Keycloak en la sesión HTTP
                session.setAttribute("accessToken", accessToken);
                session.setAttribute("idToken", idToken);
                session.setAttribute("email", email);
                session.setAttribute("fullName", fullName);
                session.setAttribute("roles", extractedAuthorities);

            } else {
                model.addAttribute("error", "Error de Keycloak: Credenciales incorrectas o problema de servidor.");
                model.addAttribute("tenantId", realm);
                System.err.println("Error de Keycloak (status no 2xx): " + tokenResponse.getStatusCode() + " - " + tokenResponse.getBody());
                response.sendRedirect("/login?error=true&tenantId=" + realm);
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            model.addAttribute("error", "Error de autenticación: Usuario o cliente no autorizado con Keycloak.");
            model.addAttribute("tenantId", realm);
            System.err.println("Error 401 Unauthorized de Keycloak: " + e.getResponseBodyAsString());
            response.sendRedirect("/login?error=true&tenantId=" + realm);
        } catch (Exception e) {
            model.addAttribute("error", "Error en la autenticación: " + (e.getMessage() != null ? e.getMessage() : "Error desconocido. Revisa logs."));
            model.addAttribute("tenantId", realm);
            System.err.println("Excepción general al autenticar: " + e.getMessage());
            e.printStackTrace();
            response.sendRedirect("/login?error=true&tenantId=" + realm);
        }
    }
}
