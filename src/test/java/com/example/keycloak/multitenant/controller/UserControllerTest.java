package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.UserService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    private String realm;
    private UserRequest userRequest;

    @BeforeEach
    void setUp() {
        realm = "plexus";
        userRequest = new UserRequest();
        userRequest.setUsername("user");
        userRequest.setEmail("user@gmail.com");
        userRequest.setFirstName("Test");
        userRequest.setLastName("User");
        userRequest.setRole("USER");
    }

    @Test
    @DisplayName("registerUser debería retornar CREATED con el response del service")
    void registerUser_shouldReturnCreated() {
        Map<String, Object> serviceResponse = new HashMap<>();
        serviceResponse.put("message", "Usuario registrado correctamente");
        serviceResponse.put("tenantId", realm);

        when(userService.registerUser(eq(realm), any(UserRequest.class))).thenReturn(serviceResponse);

        ResponseEntity<Map<String, Object>> responseEntity = userController.registerUser(realm, userRequest);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.CREATED, responseEntity.getStatusCode());
        assertEquals(serviceResponse, responseEntity.getBody());

        verify(userService, times(1)).registerUser(eq(realm), any(UserRequest.class));
    }

    @Test
    @DisplayName("getAllUsers debería retornar la lista de usuarios del service")
    void getAllUsers_shouldReturnListOfUsers() {
        List<UserRepresentation> users = new ArrayList<>();
        UserRepresentation user = new UserRepresentation();
        user.setUsername("testuser");
        users.add(user);

        when(userService.getAllUsers(realm)).thenReturn(users);

        ResponseEntity<List<UserRepresentation>> responseEntity = userController.getAllUsers(realm);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(users, responseEntity.getBody());

        verify(userService, times(1)).getAllUsers(realm);
    }

    @Test
    @DisplayName("updateUser debería llamar al service y retornar OK")
    void updateUser_shouldReturnOk() {
        UUID userId = UUID.randomUUID();

        doNothing().when(userService).updateUser(eq(realm), eq(userId.toString()), any(UserRequest.class));

        ResponseEntity<Void> responseEntity = userController.updateUser(realm, userId, userRequest);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());

        verify(userService, times(1)).updateUser(eq(realm), eq(userId.toString()), any(UserRequest.class));
    }

    @Test
    @DisplayName("deleteUser debería llamar al service y retornar NO_CONTENT")
    void deleteUser_shouldReturnNoContent() {
        UUID userId = UUID.randomUUID();

        doNothing().when(userService).deleteUser(eq(realm), eq(userId.toString()));

        ResponseEntity<Void> responseEntity = userController.deleteUser(realm, userId);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.NO_CONTENT, responseEntity.getStatusCode());

        verify(userService, times(1)).deleteUser(eq(realm), eq(userId.toString()));
    }
}
