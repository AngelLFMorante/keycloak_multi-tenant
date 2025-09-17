package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.AppProperties;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import com.example.keycloak.multitenant.service.mail.MailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link RegistrationFlowService}.
 * Verifica el flujo de registro de usuario, incluyendo la generación de tokens
 * y el envío de correos electrónicos.
 */
@ExtendWith(MockitoExtension.class)
class RegistrationFlowServiceTest {

    @Mock
    private PasswordTokenProvider tokenProvider;

    @Mock
    private MailService mailService;

    @Mock
    private AppProperties appProperties;

    @InjectMocks
    private RegistrationFlowService registrationFlowService;

    private String realmPath;
    private String userId;
    private UserRequest userRequest;
    private String token;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        realmPath = "my_realm";
        userId = "test-user-id";
        userRequest = new UserRequest("testuser", "test@example.com", "John", "Doe", "user");
        token = "sample-jwt-token";
        baseUrl = "https://localhost:8080";

        when(tokenProvider.generateToken(userId)).thenReturn(token);
        when(appProperties.getBaseUrl()).thenReturn(baseUrl);
    }

    @Test
    @DisplayName("Debería iniciar el flujo de contraseña y enviar el email con el enlace correcto")
    void startSetPasswordFlow_shouldGenerateTokenAndSendEmail() {
        registrationFlowService.startSetPasswordFlow(realmPath, userId, userRequest);

        verify(tokenProvider, times(1)).generateToken(userId);

        String expectedLink = String.format("%s/%s/password/verify?token=%s", baseUrl, realmPath, token);
        verify(mailService, times(1)).sendSetPasswordEmail(userRequest.email(), userRequest.username(), expectedLink);
    }
}
