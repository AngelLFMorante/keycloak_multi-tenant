package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import org.springframework.stereotype.Service;

@Service
public class PasswordFlowService {

    private final PasswordTokenProvider tokenProvider;
    private final UserService userService;

    public PasswordFlowService(PasswordTokenProvider tokenProvider, UserService userService) {
        this.tokenProvider = tokenProvider;
        this.userService = userService;
    }

    /**
     * Valida el token enviado por email y habilita/verifica email del usuario.
     */
    public void verifyEmail(String realm, String token) {
        String userId = tokenProvider.validateAndGetUserId(token);
        // Habilitamos al usuario y marcamos email como verificado
        userService.enableAndVerifyEmail(realm, userId);
    }

    /**
     * Valida token y establece la nueva contraseña del usuario.
     */
    public void setPassword(String realm, String token, String password) {
        String userId = tokenProvider.validateAndGetUserId(token);
        userService.resetUserPassword(realm, userId, password);
    }
}
