package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.LoginService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para la clase KeycloakChangeOwnPasswordService, utilizando Mockito.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for KeycloakChangeOwnPasswordService")
class KeycloakChangeOwnPasswordServiceTest {

    @Mock
    private LoginService loginService;

    @Mock
    private KeycloakUserService keycloakUserService;

    @InjectMocks
    private KeycloakChangeOwnPasswordService keycloakChangeOwnPasswordService;

    private String realm;
    private String client;
    private String userId;
    private String username;
    private String currentPassword;
    private String newPassword;

    @BeforeEach
    void setUp() {
        realm = "test-realm";
        client = "test-client";
        userId = "test-user-id";
        username = "test-user";
        currentPassword = "old-password";
        newPassword = "new-password";
    }

    @Test
    @DisplayName("should change password successfully when login and reset are successful")
    void changePassword_shouldBeSuccessful_whenServicesSucceed() {
        when(loginService.authenticate(realm, client, username, currentPassword))
                .thenReturn(mock(LoginResponse.class));
        doNothing().when(keycloakUserService).resetUserPassword(realm, userId, newPassword);

        keycloakChangeOwnPasswordService.changePassword(realm, client, userId, username, currentPassword, newPassword);

        verify(loginService, times(1)).authenticate(realm, client, username, currentPassword);
        verify(keycloakUserService, times(1)).resetUserPassword(realm, userId, newPassword);
    }

    @Test
    @DisplayName("should re-throw UNAUTHORIZED exception from LoginService")
    void changePassword_shouldThrowUnauthorized_whenLoginFails() {
        ResponseStatusException unauthorizedEx = new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Password incorrecta.");
        doThrow(unauthorizedEx).when(loginService).authenticate(realm, client, username, currentPassword);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () ->
                keycloakChangeOwnPasswordService.changePassword(realm, client, userId, username, currentPassword, newPassword)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, thrown.getStatusCode());
        verify(loginService, times(1)).authenticate(realm, client, username, currentPassword);
        verify(keycloakUserService, never()).resetUserPassword(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("should re-throw other exceptions from LoginService")
    void changePassword_shouldThrowOtherException_whenLoginServiceFails() {
        ResponseStatusException badRequestEx = new ResponseStatusException(HttpStatus.BAD_REQUEST, "Datos de login inválidos.");
        doThrow(badRequestEx).when(loginService).authenticate(realm, client, username, currentPassword);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () ->
                keycloakChangeOwnPasswordService.changePassword(realm, client, userId, username, currentPassword, newPassword)
        );

        assertEquals(HttpStatus.BAD_REQUEST, thrown.getStatusCode());
        verify(loginService, times(1)).authenticate(realm, client, username, currentPassword);
        verify(keycloakUserService, never()).resetUserPassword(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("should throw NOT_FOUND when KeycloakUserService throws NotFoundException")
    void changePassword_shouldThrowNotFound_whenUserNotFound() {
        when(loginService.authenticate(realm, client, username, currentPassword))
                .thenReturn(mock(LoginResponse.class));

        doThrow(NotFoundException.class).when(keycloakUserService).resetUserPassword(realm, userId, newPassword);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () ->
                keycloakChangeOwnPasswordService.changePassword(realm, client, userId, username, currentPassword, newPassword)
        );

        assertEquals(HttpStatus.NOT_FOUND, thrown.getStatusCode());
        verify(loginService, times(1)).authenticate(realm, client, username, currentPassword);
        verify(keycloakUserService, times(1)).resetUserPassword(realm, userId, newPassword);
    }

    @Test
    @DisplayName("should re-throw WebApplicationException from KeycloakUserService as ResponseStatusException")
    void changePassword_shouldThrowWebApplicationException_whenKeycloakUserServiceFails() {
        when(loginService.authenticate(realm, client, username, currentPassword))
                .thenReturn(mock(LoginResponse.class));

        WebApplicationException webEx = mock(WebApplicationException.class);
        when(webEx.getResponse()).thenReturn(mock(jakarta.ws.rs.core.Response.class));
        when(webEx.getResponse().getStatus()).thenReturn(500);
        doThrow(webEx).when(keycloakUserService).resetUserPassword(realm, userId, newPassword);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () ->
                keycloakChangeOwnPasswordService.changePassword(realm, client, userId, username, currentPassword, newPassword)
        );

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, thrown.getStatusCode());
        verify(loginService, times(1)).authenticate(realm, client, username, currentPassword);
        verify(keycloakUserService, times(1)).resetUserPassword(realm, userId, newPassword);
    }
}
