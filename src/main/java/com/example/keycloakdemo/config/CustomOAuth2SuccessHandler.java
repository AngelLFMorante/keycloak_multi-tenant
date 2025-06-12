package com.example.keycloakdemo.config;

import com.example.keycloakdemo.models.AppUser;
import com.example.keycloakdemo.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = authToken.getPrincipal();

        String username = oauthUser.getAttribute("preferred_username");
        String email = oauthUser.getAttribute("email");
        String tenantId = authToken.getAuthorizedClientRegistrationId(); // 'plexus'

        // Registrar o actualizar usuario en la base de datos
        AppUser user = userService.processOAuthPostLogin(username, email, tenantId);

        // Verificar si está aprobado
        if (!user.isEnabled()) {
            response.sendRedirect("/pending_approval");
        } else {
            response.sendRedirect("/home");
        }
    }
}
