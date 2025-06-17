package com.example.keycloakdemo.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Maneja el redireccionamiento tras un login exitoso según el tenant.
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final TenantProperties tenantProperties;

    public CustomAuthenticationSuccessHandler(TenantProperties tenantProperties) {
        this.tenantProperties = tenantProperties;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            System.out.println("Login exitoso para tenant: " + registrationId);

            if (tenantProperties.isValidTenant(registrationId)) {
                response.sendRedirect("/" + registrationId + "/home");
                return;
            }
        }

        // Fallback
        response.sendRedirect("/");
    }
}
