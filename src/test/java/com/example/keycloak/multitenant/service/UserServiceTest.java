package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.model.UserWithRoles;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUserService;
import com.example.keycloak.multitenant.service.utils.KeycloakConfigService;
import java.util.ArrayList;
import java.util.Collections;
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
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private KeycloakUserService keycloakUserService;

    @Mock
    private KeycloakConfigService utilsService;

    @InjectMocks
    private UserService userService;

    private UserRequest userRequest;

    @BeforeEach
    void setUp() {
        userRequest = new UserRequest(
                "user",
                "user@gmail.com",
                "Test",
                "User",
                "USER"
        );
    }

    @Test
    @DisplayName("registerUser debería crear usuario si realm existe y email no está registrado")
    void registerUser_shouldCreateUserSuccessfully() {
        when(utilsService.resolveRealm("plexus")).thenReturn("plexus-realm");
        when(keycloakUserService.userExistsByEmail("plexus-realm", userRequest.email())).thenReturn(false);
        doNothing().when(keycloakUserService).createUserWithRole(eq("plexus-realm"), anyString(), any(UserRequest.class), anyString());

        Map<String, Object> response = userService.registerUser("plexus", userRequest);

        assertNotNull(response);
        assertEquals("Usuario registrado. Esperando aprobacion de administrador.", response.get("message"));
        assertEquals("plexus", response.get("tenantId"));
        assertEquals("plexus-realm", response.get("keycloakRealm"));

        verify(keycloakUserService, times(1)).createUserWithRole(eq("plexus-realm"), anyString(), eq(userRequest), anyString());
    }

    @DisplayName("registerUser debería lanzar excepción si el realm no existe")
    void registerUser_shouldThrowExceptionIfRealmNotFound() {
        when(utilsService.resolveRealm("unknownRealm")).thenReturn(null);
        assertThrows(ResponseStatusException.class, () -> userService.registerUser("unknownRealm", userRequest));

        verify(keycloakUserService, never()).createUserWithRole(anyString(), anyString(), any(), anyString());
    }

    @Test
    @DisplayName("registerUser debería lanzar excepción si el email ya existe")
    void registerUser_shouldThrowExceptionIfEmailExists() {
        when(utilsService.resolveRealm("plexus")).thenReturn("plexus-realm");
        when(keycloakUserService.userExistsByEmail("plexus-realm", userRequest.email())).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> userService.registerUser("plexus", userRequest));

        assertEquals("El email 'user@gmail.com' ya está registrado.", ex.getMessage());
        verify(keycloakUserService, never()).createUserWithRole(anyString(), anyString(), any(), anyString());
    }

    @Test
    @DisplayName("getAllUsers debería retornar lista de DTOs de usuarios con roles")
    void getAllUsers_shouldReturnUserWithRolesList() {
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

        when(utilsService.resolveRealm("plexus")).thenReturn("plexus-realm");
        when(keycloakUserService.getAllUsersWithRoles("plexus-realm")).thenReturn(usersWithRoles);

        List<UserWithRoles> result = userService.getAllUsers("plexus");

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("testuser", result.get(0).username());
        assertEquals("user", result.get(0).roles().get(0));

        verify(keycloakUserService, times(1)).getAllUsersWithRoles("plexus-realm");
    }

    @Test
    @DisplayName("updateUser debería delegar en keycloakUserService")
    void updateUser_shouldDelegateTokeycloakUserService() {
        when(utilsService.resolveRealm("plexus")).thenReturn("plexus-realm");
        doNothing().when(keycloakUserService).updateUser(eq("plexus-realm"), anyString(), any(UserRequest.class));

        userService.updateUser("plexus", "12345", userRequest);

        verify(keycloakUserService, times(1)).updateUser("plexus-realm", "12345", userRequest);
    }

    @Test
    @DisplayName("deleteUser debería delegar en keycloakUserService")
    void deleteUser_shouldDelegateTokeycloakUserService() {
        when(utilsService.resolveRealm("plexus")).thenReturn("plexus-realm");
        doNothing().when(keycloakUserService).deleteUser(eq("plexus-realm"), anyString());

        userService.deleteUser("plexus", "12345");

        verify(keycloakUserService, times(1)).deleteUser("plexus-realm", "12345");
    }

    @Test
    @DisplayName("getUserById debería devolver un usuario con roles si es encontrado")
    void getUserById_shouldReturnUserWithRoles_WhenUserIsFound() {
        String realm = "testRealm";
        String keycloakRealm = "testRealm-keycloak";
        String userId = UUID.randomUUID().toString();
        UserWithRoles mockUser = new UserWithRoles(
                userId,
                "testuser",
                "test@test.com",
                "Test",
                "User",
                true,
                true,
                List.of("user")
        );

        when(utilsService.resolveRealm(realm)).thenReturn(keycloakRealm);
        when(keycloakUserService.getUserByIdWithRoles(keycloakRealm, userId)).thenReturn(mockUser);

        UserWithRoles result = userService.getUserById(realm, userId);

        assertNotNull(result);
        assertEquals(userId, result.id());
        assertEquals(mockUser.username(), result.username());
        verify(utilsService, times(1)).resolveRealm(realm);
        verify(keycloakUserService, times(1)).getUserByIdWithRoles(keycloakRealm, userId);
    }
}
