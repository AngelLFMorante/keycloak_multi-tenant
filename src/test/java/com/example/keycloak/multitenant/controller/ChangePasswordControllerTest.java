package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.controller.api.ChangePasswordController;
import com.example.keycloak.multitenant.model.ChangePasswordRequest;
import com.example.keycloak.multitenant.service.ChangeOwnPasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for ChangePasswordController using MockitoExtension")
class ChangePasswordControllerTest {

    @Mock
    private ChangeOwnPasswordService changeOwnPasswordService;

    @InjectMocks
    private ChangePasswordController changePasswordController;

    private String userId;
    private String realm;
    private String client;
    private ChangePasswordRequest request;

    @BeforeEach
    void setUp() {
        userId = "test-user-id";
        realm = "test-realm";
        client = "test-client";
        request = new ChangePasswordRequest("test-user", "old-password", "new-password");
    }

    @Test
    @DisplayName("should change password successfully and return 204 NO_CONTENT")
    void changePassword_shouldReturnNoContent_whenSuccessful() {
        doNothing().when(changeOwnPasswordService).changeOwnPassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        ResponseEntity<Void> response = changePasswordController.changePassword(userId, realm, client, request);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(changeOwnPasswordService, times(1)).changeOwnPassword(
                realm,
                client,
                userId,
                request.username(),
                request.currentPassword(),
                request.newPassword()
        );
    }

    @Test
    @DisplayName("should return 400 BAD_REQUEST when service throws ResponseStatusException with BAD_REQUEST")
    void changePassword_shouldReturnBadRequest_whenServiceThrowsBadRequest() {
        doThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request message"))
                .when(changeOwnPasswordService)
                .changeOwnPassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            changePasswordController.changePassword(userId, realm, client, request);
        });

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }

    @Test
    @DisplayName("should return 401 UNAUTHORIZED when service throws ResponseStatusException with UNAUTHORIZED")
    void changePassword_shouldReturnUnauthorized_whenServiceThrowsUnauthorized() {
        doThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized message"))
                .when(changeOwnPasswordService)
                .changeOwnPassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            changePasswordController.changePassword(userId, realm, client, request);
        });

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    @DisplayName("should return 404 NOT_FOUND when service throws ResponseStatusException with NOT_FOUND")
    void changePassword_shouldReturnNotFound_whenServiceThrowsNotFound() {
        doThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Not found message"))
                .when(changeOwnPasswordService)
                .changeOwnPassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
            changePasswordController.changePassword(userId, realm, client, request);
        });

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
    }

    @Test
    @DisplayName("should return 500 INTERNAL_SERVER_ERROR when service throws RuntimeException")
    void changePassword_shouldReturnInternalServerError_whenServiceThrowsRuntimeException() {
        doThrow(new RuntimeException("Internal error"))
                .when(changeOwnPasswordService)
                .changeOwnPassword(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            changePasswordController.changePassword(userId, realm, client, request);
        });

        assertEquals("Internal error", exception.getMessage());
    }
}
