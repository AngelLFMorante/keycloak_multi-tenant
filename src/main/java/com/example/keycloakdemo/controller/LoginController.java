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
import org.springframework.security.core.context.SecurityContext; // Importar SecurityContext
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository; // Importar SecurityContextRepository
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

@Controller
public class LoginController {

    @Value("${keycloak.auth-server-url}")
    private String keycloakBaseUrl;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthenticationManager authenticationManager;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final SecurityContextRepository securityContextRepository; // Inyección de SecurityContextRepository

    public LoginController(AuthenticationManager authenticationManager,
                           AuthenticationSuccessHandler authenticationSuccessHandler,
                           SecurityContextRepository securityContextRepository) { // Constructor para inyección
        this.authenticationManager = authenticationManager;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.securityContextRepository = securityContextRepository;
    }

    @PostMapping("/{realm}/do_login")
    public void doLogin(@PathVariable String realm,
                        @RequestParam String username,
                        @RequestParam String password,
                        Model model,
                        HttpSession session,
                        HttpServletRequest request,
                        HttpServletResponse response) throws IOException {

        String tokenUrl = keycloakBaseUrl + "/realms/" + realm + "-realm/protocol/openid-connect/token";
        String clientId = "mi-app-" + realm;

        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", clientId);
        params.add("username", username);
        params.add("password", password);
        params.add("scope", "openid");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String clientAuth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

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

                // --- INICIO DE FLUJO DE ÉXITO ---
                UsernamePasswordAuthenticationToken authenticationRequest = new UsernamePasswordAuthenticationToken(
                        preferredUsername, SecurityConfig.DUMMY_PASSWORD
                );

                Authentication authenticatedResult = authenticationManager.authenticate(authenticationRequest);

                Authentication finalAuthentication = new UsernamePasswordAuthenticationToken(
                        authenticatedResult.getPrincipal(),
                        authenticatedResult.getCredentials(),
                        extractedAuthorities
                );

                SecurityContextHolder.getContext().setAuthentication(finalAuthentication);

                // Guardar explícitamente el SecurityContext en la sesión
                SecurityContext sc = SecurityContextHolder.getContext();
                securityContextRepository.saveContext(sc, request, response);

                authenticationSuccessHandler.onAuthenticationSuccess(request, response, finalAuthentication);

                session.setAttribute("accessToken", accessToken);
                session.setAttribute("idToken", idToken);
                session.setAttribute("email", email);
                session.setAttribute("fullName", fullName);
                session.setAttribute("roles", extractedAuthorities);

                // No hay return aquí, ya que el AuthenticationSuccessHandler maneja la redirección.

            } else {
                model.addAttribute("error", "Error de Keycloak: Credenciales incorrectas.");
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