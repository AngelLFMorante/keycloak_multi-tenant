package com.example.keycloakdemo.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // Copia el mismo tenantMapping que usas en DynamicClientRegistrationRepository
    private final Map<String, String[]> tenantMapping = Map.of(
            "plexus", new String[]{"plexus-realm", "mi-app-plexus"},
            "inditex", new String[]{"inditex-realm", "mi-app-inditex"}
            // ... otros tenants
    );

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            System.out.println("Login exitoso para tenant: " + registrationId);

            // registrationId será 'plexus', 'inditex', etc
            // Solo aseguramos que sea válido
            if (tenantMapping.containsKey(registrationId)) {
                // Redirigir al path dinámico
                response.sendRedirect("/" + registrationId + "/home");
                return;
            }
        }
        // En caso de fallo, redirigir al root
        response.sendRedirect("/");
    }
}

