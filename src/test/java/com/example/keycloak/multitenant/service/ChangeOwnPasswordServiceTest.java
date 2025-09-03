package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.service.keycloak.KeycloakChangeOwnPasswordService;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Pruebas unitarias para la clase ChangeOwnPasswordService, utilizando Mockito.
 * Valida la lógica de orquestación y las validaciones de alto nivel antes
 * de delegar a los servicios de Keycloak.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for ChangeOwnPasswordService")
class ChangeOwnPasswordServiceTest {

    @Mock
    private KeycloakChangeOwnPasswordService keycloakChangeOwnPasswordService;

    @InjectMocks
    private ChangeOwnPasswordService changeOwnPasswordService;

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
    @DisplayName("should delegate password change successfully when all data is valid")
    void changeOwnPassword_shouldDelegateToKeycloakService_whenDataIsValid() {
        doNothing().when(keycloakChangeOwnPasswordService).changePassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        changeOwnPasswordService.changeOwnPassword(realm, client, userId, username, currentPassword, newPassword);

        verify(keycloakChangeOwnPasswordService, times(1)).changePassword(realm, client, userId, username, currentPassword, newPassword);
    }

    @Test
    @DisplayName("should throw BAD_REQUEST when current password is null")
    void changeOwnPassword_shouldThrowBadRequest_whenCurrentPasswordIsNull() {
        String currentPasswordNull = null;

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                changeOwnPasswordService.changeOwnPassword(realm, client, userId, username, currentPasswordNull, newPassword)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertEquals("La password actual y la nueva no pueden estar vacías.", exception.getReason());

        verify(keycloakChangeOwnPasswordService, never()).changePassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("should throw BAD_REQUEST when current password is empty")
    void changeOwnPassword_shouldThrowBadRequest_whenCurrentPasswordIsEmpty() {
        String currentPasswordEmpty = "";

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                changeOwnPasswordService.changeOwnPassword(realm, client, userId, username, currentPasswordEmpty, newPassword)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertEquals("La password actual y la nueva no pueden estar vacías.", exception.getReason());

        verify(keycloakChangeOwnPasswordService, never()).changePassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("should throw BAD_REQUEST when new password is null")
    void changeOwnPassword_shouldThrowBadRequest_whenNewPasswordIsNull() {
        String newPasswordNull = null;

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                changeOwnPasswordService.changeOwnPassword(realm, client, userId, username, currentPassword, newPasswordNull)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertEquals("La password actual y la nueva no pueden estar vacías.", exception.getReason());

        verify(keycloakChangeOwnPasswordService, never()).changePassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("should throw BAD_REQUEST when new password is empty")
    void changeOwnPassword_shouldThrowBadRequest_whenNewPasswordIsEmpty() {
        String newPasswordEmpty = "";

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                changeOwnPasswordService.changeOwnPassword(realm, client, userId, username, currentPassword, newPasswordEmpty)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertEquals("La password actual y la nueva no pueden estar vacías.", exception.getReason());

        verify(keycloakChangeOwnPasswordService, never()).changePassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("should propagate exceptions thrown by KeycloakChangeOwnPasswordService")
    void changeOwnPassword_shouldPropagateException_whenKeycloakServiceThrows() {
        ResponseStatusException delegatedException = new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Password actual incorrecta.");
        doThrow(delegatedException).when(keycloakChangeOwnPasswordService).changePassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () ->
                changeOwnPasswordService.changeOwnPassword(realm, client, userId, username, currentPassword, newPassword)
        );
        
        assertEquals(delegatedException, thrown);
    }
}
