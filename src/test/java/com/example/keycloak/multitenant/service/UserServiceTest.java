package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    private KeycloakService keycloakService;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private UserService userService;

    private UserRequest userRequest;
    private Map<String, String> realmMapping;

    @BeforeEach
    void setUp() {
        userRequest = new UserRequest();
        userRequest.setUsername("user");
        userRequest.setEmail("user@gmail.com");
        userRequest.setFirstName("Test");
        userRequest.setLastName("User");
        userRequest.setRole("USER");

        realmMapping = new HashMap<>();
        realmMapping.put("plexus", "plexus-realm");

        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
    }

    @Test
    @DisplayName("registerUser debería crear usuario si realm existe y email no está registrado")
    void registerUser_shouldCreateUserSuccessfully() {
        when(keycloakService.userExistsByEmail("plexus-realm", userRequest.getEmail())).thenReturn(false);
        doNothing().when(keycloakService).createUserWithRole(eq("plexus-realm"), any(UserRequest.class), anyString());

        Map<String, Object> response = userService.registerUser("plexus", userRequest);

        assertNotNull(response);
        assertEquals("Usuario registrado. Esperando aprobacion de administrador.", response.get("message"));
        assertEquals("plexus", response.get("tenantId"));
        assertEquals("plexus-realm", response.get("keycloakRealm"));

        verify(keycloakService, times(1)).createUserWithRole(eq("plexus-realm"), eq(userRequest), anyString());
    }

    @Test
    @DisplayName("registerUser debería lanzar excepción si el realm no existe")
    void registerUser_shouldThrowExceptionIfRealmNotFound() {
        assertThrows(ResponseStatusException.class, () -> userService.registerUser("unknownRealm", userRequest));

        verify(keycloakService, never()).createUserWithRole(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("registerUser debería lanzar excepción si el email ya existe")
    void registerUser_shouldThrowExceptionIfEmailExists() {
        when(keycloakService.userExistsByEmail("plexus-realm", userRequest.getEmail())).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> userService.registerUser("plexus", userRequest));

        assertEquals("El email 'user@gmail.com' ya está registrado.", ex.getMessage());
        verify(keycloakService, never()).createUserWithRole(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("getAllUsers debería retornar lista del KeycloakService")
    void getAllUsers_shouldReturnUserList() {
        List<UserRepresentation> users = new ArrayList<>();
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user");
        users.add(user);

        when(keycloakService.getAllUsers("plexus-realm")).thenReturn(users);

        List<UserRepresentation> result = userService.getAllUsers("plexus");

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("user", result.get(0).getUsername());

        verify(keycloakService, times(1)).getAllUsers("plexus-realm");
    }

    @Test
    @DisplayName("getAllUsers debería lanzar ResponseStatusException si el realm no existe")
    void getAllUsers_shouldThrowExceptionIfRealmNotFound() {
        realmMapping.clear();
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> userService.getAllUsers("unknownRealm"));

        assertEquals("404 NOT_FOUND \"Tenant unknownRealm no reconocido.\"", ex.getMessage());
        verify(keycloakService, never()).getAllUsers(anyString());
    }

    @Test
    @DisplayName("updateUser debería delegar en keycloakService")
    void updateUser_shouldDelegateToKeycloakService() {
        doNothing().when(keycloakService).updateUser(eq("plexus-realm"), anyString(), any(UserRequest.class));

        userService.updateUser("plexus", "12345", userRequest);

        verify(keycloakService, times(1)).updateUser("plexus-realm", "12345", userRequest);
    }

    @Test
    @DisplayName("deleteUser debería delegar en keycloakService")
    void deleteUser_shouldDelegateToKeycloakService() {
        doNothing().when(keycloakService).deleteUser(eq("plexus-realm"), anyString());

        userService.deleteUser("plexus", "12345");

        verify(keycloakService, times(1)).deleteUser("plexus-realm", "12345");
    }
}
