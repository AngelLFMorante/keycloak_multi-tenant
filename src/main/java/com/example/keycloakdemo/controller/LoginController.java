package com.example.keycloakdemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Controller
public class LoginController {

    @Value("${keycloak.auth-server-url}")
    private String keycloakBaseUrl;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret; // Este valor DEBE coincidir con Keycloak

    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping("/{realm}/do_login")
    public String doLogin(@PathVariable String realm,
                          @RequestParam String username,
                          @RequestParam String password,
                          Model model,
                          HttpSession session) {

        String tokenUrl = keycloakBaseUrl + "/realms/" + realm + "-realm/protocol/openid-connect/token";
        String clientId = "mi-app-" + realm;

        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", clientId);
        params.add("username", username);
        params.add("password", password);
        params.add("scope", "openid"); // Mantener openid si quieres el id_token (aunque no se use para roles)

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String clientAuth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes(StandardCharsets.UTF_8));
        headers.set("Authorization", "Basic " + encodedAuth);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                JsonNode node = objectMapper.readTree(response.getBody());

                String accessToken = node.get("access_token").asText();
                String idToken = node.has("id_token") ? node.get("id_token").asText() : null; // idToken puede ser null

                session.setAttribute("accessToken", accessToken);
                // Si el idToken es nulo, esta línea no añadirá nada, lo cual está bien.
                session.setAttribute("idToken", idToken);
                session.setAttribute("username", username);


                // --- INICIO DE LA LÓGICA DE EXTRACCIÓN DE ROLES Y DATOS DE USUARIO ---
                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                String email = null;
                String fullName = null;
                String preferredUsername = username; // Por defecto el username de login

                // **PASO CLAVE: Decodificar el ACCESS TOKEN para obtener los roles y otros datos**
                if (accessToken != null) { // Asegúrate de que tienes un access token
                    DecodedJWT decodedAccessToken = JWT.decode(accessToken);

                    // Extraer roles de 'realm_access' del ACCESS TOKEN
                    Map<String, Object> realmAccess = decodedAccessToken.getClaim("realm_access").asMap();
                    if (realmAccess != null && realmAccess.containsKey("roles")) {
                        @SuppressWarnings("unchecked")
                        List<String> realmRoles = (List<String>) realmAccess.get("roles");
                        if (realmRoles != null) {
                            for (String role : realmRoles) {
                                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                            }
                        }
                    }

                    // Extraer roles de 'resource_access' del ACCESS TOKEN
                    Map<String, Object> resourceAccess = decodedAccessToken.getClaim("resource_access").asMap();
                    if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
                        if (clientAccess != null && clientAccess.containsKey("roles")) {
                            @SuppressWarnings("unchecked")
                            List<String> clientRoles = (List<String>) clientAccess.get("roles");
                            if (clientRoles != null) {
                                for (String role : clientRoles) {
                                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                                }
                            }
                        }
                    }

                    // Extraer email, fullName, preferred_username del ACCESS TOKEN (si existen)
                    // Estos claims pueden estar en el Access Token si los scopes adecuados fueron pedidos
                    // y Keycloak los incluye para ese tipo de token/flujo.
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
                    // Si no hay access token (muy raro si la respuesta es 2xx), no podemos extraer roles
                    System.err.println("Advertencia: Access Token es nulo en una respuesta exitosa.");
                }

                // Usar el preferredUsername para la autenticación si está disponible
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        preferredUsername, null, authorities
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);

                session.setAttribute("email", email);
                session.setAttribute("fullName", fullName);
                session.setAttribute("roles", authorities); // Ahora esta lista debería contener roles
                // --- FIN DE LA LÓGICA DE EXTRACCIÓN DE ROLES Y DATOS DE USUARIO ---


                return "redirect:/" + realm + "/home";
            } else {
                model.addAttribute("error", "Credenciales incorrectas (estado no 2xx)");
                model.addAttribute("tenantId", realm);
                System.err.println("Error: Respuesta de Keycloak no 2xx: " + response.getStatusCode() + " - " + response.getBody());
                return "login";
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            model.addAttribute("error", "Credenciales de usuario o cliente incorrectas. Revisa usuario/contraseña y el secreto del cliente en Keycloak.");
            model.addAttribute("tenantId", realm);
            System.err.println("Error 401 Unauthorized: " + e.getResponseBodyAsString());
            return "login";
        } catch (Exception e) {
            model.addAttribute("error", "Error en la autenticación: " + (e.getMessage() != null ? e.getMessage() : "Error desconocido"));
            model.addAttribute("tenantId", realm);
            System.err.println("Error general de autenticación: " + e.getMessage());
            e.printStackTrace();
            return "login";
        }
    }
}