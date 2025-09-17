package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.UserService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
        userRequest = new UserRequest(
                "user",
                "user@gmail.com",
                "Test",
                "User",
                "USER"
        );
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
    @DisplayName("getUserById debería retornar un usuario con roles")
    void getUserById_shouldReturnUserWithRoles() {
        UUID userId = UUID.randomUUID();
        UserWithRoles userDetails = new UserWithRoles(
                userId.toString(),
                "testuser",
                "test@example.com",
                "Test",
                "User",
                true,
                true,
                List.of("ADMIN")
        );

        when(userService.getUserById(eq(realm), eq(userId.toString()))).thenReturn(userDetails);

        ResponseEntity<UserWithRoles> responseEntity = userController.getUserById(realm, userId);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(userDetails, responseEntity.getBody());

        verify(userService, times(1)).getUserById(eq(realm), eq(userId.toString()));
    }

    @Test
    @DisplayName("getAllUsers debería retornar una lista de usuarios con roles")
    void getAllUsers_shouldReturnListOfUsersWithRoles() {
        List<UserWithRoles> usersWithRoles = Collections.singletonList(
                new UserWithRoles(
                        "123",
                        "testuser",
                        "test@test.com",
                        "Test",
                        "User",
                        true,
                        true,
                        List.of("user")
                )
        );

        when(userService.getAllUsers(realm)).thenReturn(usersWithRoles);

        ResponseEntity<List<UserWithRoles>> responseEntity = userController.getAllUsers(realm);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(usersWithRoles, responseEntity.getBody());

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

    @Test
    @DisplayName("getUserByEmail debería retornar un usuario con roles")
    void getUserByEmail_shouldReturnUserWithRoles() {
        String email = "testuser@example.com";
        UserWithRoles userDetails = new UserWithRoles(
                UUID.randomUUID().toString(),
                "testuser",
                email,
                "Test",
                "User",
                true,
                true,
                List.of("USER")
        );

        when(userService.getUserByEmail(eq(realm), eq(email))).thenReturn(userDetails);

        ResponseEntity<UserWithRoles> responseEntity = userController.getUserByEmail(realm, email);

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(userDetails, responseEntity.getBody());

        verify(userService, times(1)).getUserByEmail(eq(realm), eq(email));
    }

    @Test
    @DisplayName("getUsersByAttributes should return a list of users with attributes")
    void getUsersByAttributes_shouldReturnUsersWithAttributes() {
        String organization = "Plexus";
        String subsidiary = "ES";
        String department = "IT";

        List<UserWithRolesAndAttributes> usersWithAttributes = new ArrayList<>();
        usersWithAttributes.add(new UserWithRolesAndAttributes(
                new UserWithRoles(
                        UUID.randomUUID().toString(),
                        "testuser",
                        "test@example.com",
                        "Test",
                        "User",
                        true,
                        true,
                        List.of("user")
                ),
                Map.of("organization", List.of(organization), "subsidiary", List.of(subsidiary), "department", List.of(department))
        ));

        when(userService.getUsersByAttributes(eq(realm), any(UserSearchCriteria.class)))
                .thenReturn(usersWithAttributes);

        ResponseEntity<List<UserWithRolesAndAttributes>> responseEntity = userController.getUsersByAttributes(
                realm, organization, subsidiary, department
        );

        assertNotNull(responseEntity);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(usersWithAttributes.size(), responseEntity.getBody().size());
        assertEquals(usersWithAttributes, responseEntity.getBody());

        verify(userService, times(1)).getUsersByAttributes(eq(realm), any(UserSearchCriteria.class));
    }
}
