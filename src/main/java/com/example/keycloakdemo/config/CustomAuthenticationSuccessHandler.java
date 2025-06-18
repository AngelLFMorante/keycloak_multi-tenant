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

/**
 * Manejador que redirige al home del tenant después de un login exitoso.
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // Mapeo de tenants: nombre del tenant -> [realm, clientId]
    private final Map<String, String[]> tenantMapping = Map.of(
            "plexus", new String[]{"plexus-realm", "mi-app-plexus"},
            "inditex", new String[]{"inditex-realm", "mi-app-inditex"}
    );

    /**
     * Redirige a la ruta /{tenant}/home luego de un login exitoso.
     *
     * @param request        Solicitud HTTP.
     * @param response       Respuesta HTTP.
     * @param authentication Autenticación del usuario.
     * @throws IOException      Error de redirección.
     * @throws ServletException Error de servlet.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            System.out.println("Login exitoso para tenant: " + registrationId);

            if (tenantMapping.containsKey(registrationId)) {
                response.sendRedirect("/" + registrationId + "/home");
                return;
            }
        }
        response.sendRedirect("/");
    }
}
