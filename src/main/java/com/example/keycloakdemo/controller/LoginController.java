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

/**
 * Controlador para gestionar el proceso de login manual de usuarios contra Keycloak
 * utilizando el flujo de Password Grant Type, e integrando la autenticación con Spring Security.
 * También maneja las redirecciones en caso de éxito o error en el proceso de autenticación.
 */
@Controller
public class LoginController {

    /**
     * URL base del servidor de autenticación de Keycloak, inyectada desde las propiedades.
     */
    @Value("${keycloak.auth-server-url}")
    private String keycloakBaseUrl;

    /**
     * Secreto del cliente de la aplicación, utilizado para la autenticación del cliente
     * en Keycloak cuando se solicita un token (Password Grant Type).
     */
    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    /**
     * Objeto para la serialización/deserialización de JSON.
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Componente de Spring Security para procesar y autenticar {@link Authentication} objects.
     */
    private final AuthenticationManager authenticationManager;

    /**
     * Manejador de éxito de autenticación de Spring Security, responsable de las redirecciones
     * después de un login exitoso.
     */
    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    /**
     * Repositorio de contexto de seguridad de Spring Security, utilizado para guardar
     * y recuperar el {@link SecurityContext} en la sesión HTTP.
     */
    private final SecurityContextRepository securityContextRepository;

    /**
     * Constructor para la inyección de dependencias de Spring.
     *
     * @param authenticationManager      Instancia de {@link AuthenticationManager}.
     * @param authenticationSuccessHandler Instancia de {@link AuthenticationSuccessHandler}.
     * @param securityContextRepository  Instancia de {@link SecurityContextRepository}.
     */
    public LoginController(AuthenticationManager authenticationManager,
                           AuthenticationSuccessHandler authenticationSuccessHandler,
                           SecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.securityContextRepository = securityContextRepository;
    }

    /**
     * Maneja la solicitud POST de login de un usuario.
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

        // Construye la URL del endpoint de tokens de Keycloak para el realm específico.
        String tokenUrl = keycloakBaseUrl + "/realms/" + realm + "-realm/protocol/openid-connect/token";
        // Define el ID del cliente basado en el nombre del realm.
        String clientId = "mi-app-" + realm;

        RestTemplate restTemplate = new RestTemplate();

        // Prepara los parámetros para la solicitud POST al endpoint de tokens de Keycloak (Password Grant).
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password"); // Tipo de concesión: Password Grant.
        params.add("client_id", clientId); // ID del cliente de la aplicación.
        params.add("username", username); // Nombre de usuario para autenticar.
        params.add("password", password); // Contraseña del usuario para autenticar.
        params.add("scope", "openid"); // Scopes OpenID Connect solicitados.

        HttpHeaders headers = new HttpHeaders();
        // Establece el tipo de contenido como formulario URL-encoded.
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Prepara la autenticación básica para el cliente (Client ID:Client Secret).
        String clientAuth = clientId + ":" + clientSecret;
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
                // Parsea la respuesta JSON para extraer el access_token y id_token.
                JsonNode node = objectMapper.readTree(tokenResponse.getBody());
                String accessToken = node.get("access_token").asText();
                String idToken = node.has("id_token") ? node.get("id_token").asText() : null;

                // Guarda el nombre de usuario en la sesión (para uso de la aplicación, no de Spring Security).
                session.setAttribute("username", username);

                // Variables para almacenar los roles extraídos del token y otros detalles del usuario.
                List<SimpleGrantedAuthority> extractedAuthorities = new ArrayList<>();
                String email = null;
                String fullName = null;
                String preferredUsername = username; // Por defecto, el nombre de usuario del formulario.

                // Decodifica el Access Token JWT para extraer claims como roles, email, nombre.
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
                    // Advertencia si el Access Token es nulo a pesar de una respuesta exitosa.
                    System.err.println("Advertencia: Access Token es nulo en una respuesta exitosa de Keycloak.");
                    model.addAttribute("error", "Error interno: No se recibió Access Token de Keycloak.");
                    model.addAttribute("tenantId", realm);
                    response.sendRedirect("/login?error=true&tenantId=" + realm); // Redirige a la página de login con error.
                    return; // Termina la ejecución.
                }

                // --- INICIO DE INTEGRACIÓN CON SPRING SECURITY ---

                // 1. Crear un UsernamePasswordAuthenticationToken INAUTENTICADO.
                // Este token se usará para que el AuthenticationManager de Spring Security inicie el proceso.
                // Se le pasa el 'preferredUsername' como principal y la DUMMY_PASSWORD como credencial.
                // La DUMMY_PASSWORD debe coincidir con la configurada en SecurityConfig.userDetailsService().
                UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                        preferredUsername, SecurityConfig.DUMMY_PASSWORD
                );

                // 2. Delegar la autenticación al AuthenticationManager de Spring Security.
                // El AuthenticationManager utilizará el DaoAuthenticationProvider (configurado con UserDetailsService y PasswordEncoder dummy)
                // para "autenticar" este token. El resultado será un objeto Authentication ya marcado como autenticado.
                Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);

                // 3. Crear un NUEVO AuthenticationToken FINAL con el principal autenticado y los roles REALES.
                // Esto asegura que el SecurityContextHolder tenga el principal correcto y las autoridades
                // (roles) extraídas directamente de Keycloak.
                Authentication finalAuthentication = new UsernamePasswordAuthenticationToken(
                        authenticatedResult.getPrincipal(), // El principal (usuario) ya autenticado por el manager.
                        authenticatedResult.getCredentials(), // Las credenciales (DUMMY_PASSWORD) del token autenticado.
                        extractedAuthorities // Las autoridades (roles) REALES obtenidas de Keycloak.
                );

                // 4. Establecer el objeto Authentication FINAL en el SecurityContextHolder.
                // Esto hace que el usuario esté disponible para Spring Security en el contexto actual del hilo.
                SecurityContextHolder.getContext().setAuthentication(finalAuthentication);

                // 5. Guardar explícitamente el SecurityContext en el repositorio de contexto de seguridad.
                // Esto es vital para que la autenticación persista en la HttpSession y el usuario
                // permanezca autenticado en las siguientes peticiones.
                SecurityContext sc = SecurityContextHolder.getContext();
                securityContextRepository.saveContext(sc, request, response);

                // 6. Invocar el AuthenticationSuccessHandler para manejar la redirección post-login.
                // Este handler redirigirá al usuario a la página de inicio específica del tenant.
                authenticationSuccessHandler.onAuthenticationSuccess(request, response, finalAuthentication);

                // --- FIN DE INTEGRACIÓN CON SPRING SECURITY ---

                // Guardar los datos relevantes del token de Keycloak en la sesión HTTP
                // para que la aplicación pueda acceder a ellos si es necesario (ej. para llamar a otras APIs).
                session.setAttribute("accessToken", accessToken);
                session.setAttribute("idToken", idToken);
                session.setAttribute("email", email);
                session.setAttribute("fullName", fullName);
                session.setAttribute("roles", extractedAuthorities);

                // El método termina aquí; el AuthenticationSuccessHandler ya ha enviado la redirección.

            } else {
                // Manejo de errores si la respuesta de Keycloak no es exitosa (ej. 400 Bad Request, etc.).
                model.addAttribute("error", "Error de Keycloak: Credenciales incorrectas o problema de servidor.");
                model.addAttribute("tenantId", realm);
                System.err.println("Error de Keycloak (status no 2xx): " + tokenResponse.getStatusCode() + " - " + tokenResponse.getBody());
                response.sendRedirect("/login?error=true&tenantId=" + realm); // Redirige a login con error.
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            // Captura errores específicos de "Unauthorized" (HTTP 401) de Keycloak.
            model.addAttribute("error", "Error de autenticación: Usuario o cliente no autorizado con Keycloak.");
            model.addAttribute("tenantId", realm);
            System.err.println("Error 401 Unauthorized de Keycloak: " + e.getResponseBodyAsString());
            response.sendRedirect("/login?error=true&tenantId=" + realm); // Redirige a login con error.
        } catch (Exception e) {
            // Captura cualquier otra excepción inesperada durante el proceso de login.
            // Esto incluye posibles errores del AuthenticationManager si la configuración es incorrecta.
            model.addAttribute("error", "Error en la autenticación: " + (e.getMessage() != null ? e.getMessage() : "Error desconocido. Revisa logs."));
            model.addAttribute("tenantId", realm);
            System.err.println("Excepción general al autenticar: " + e.getMessage());
            e.printStackTrace(); // Imprime el stack trace para depuración.
            response.sendRedirect("/login?error=true&tenantId=" + realm); // Redirige a login con error.
        }
    }
}
