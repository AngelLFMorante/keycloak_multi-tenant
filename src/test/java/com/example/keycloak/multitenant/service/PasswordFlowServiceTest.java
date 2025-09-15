package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link PasswordFlowService}.
 * Verifica la lógica de orquestación del flujo de contraseñas.
 */
@ExtendWith(MockitoExtension.class)
class PasswordFlowServiceTest {

    @Mock
    private PasswordTokenProvider tokenProvider;

    @Mock
    private UserService userService;

    @InjectMocks
    private PasswordFlowService passwordFlowService;

    private String realm;
    private String token;
    private String userId;
    private String password;

    @BeforeEach
    void setUp() {
        realm = "my_realm";
        token = "test_token_123";
        userId = "test_user_id";
        password = "newPassword!@#";
    }

    @Test
    @DisplayName("Debería verificar el correo electrónico y habilitar el usuario")
    void verifyEmail_shouldVerifyEmailAndEnableUser() {
        when(tokenProvider.validateAndGetUserId(token)).thenReturn(userId);

        passwordFlowService.verifyEmail(realm, token);

        verify(tokenProvider, times(1)).validateAndGetUserId(token);
        verify(userService, times(1)).enableAndVerifyEmail(realm, userId);
    }

    @Test
    @DisplayName("Debería establecer la contraseña del usuario")
    void setPassword_shouldSetUserPassword() {
        when(tokenProvider.validateAndGetUserId(token)).thenReturn(userId);

        passwordFlowService.setPassword(realm, token, password);

        verify(tokenProvider, times(1)).validateAndGetUserId(token);
        verify(userService, times(1)).resetUserPassword(realm, userId, password);
    }

    @Test
    @DisplayName("Debería lanzar una excepción si el token no es válido")
    void shouldThrowException_whenTokenIsInvalid() {
        when(tokenProvider.validateAndGetUserId(anyString())).thenThrow(new JwtException("Token inválido"));

        assertThrows(JwtException.class, () -> passwordFlowService.verifyEmail(realm, token));
        assertThrows(JwtException.class, () -> passwordFlowService.setPassword(realm, token, password));

        verify(userService, never()).enableAndVerifyEmail(anyString(), anyString());
        verify(userService, never()).resetUserPassword(anyString(), anyString(), anyString());
    }
}
