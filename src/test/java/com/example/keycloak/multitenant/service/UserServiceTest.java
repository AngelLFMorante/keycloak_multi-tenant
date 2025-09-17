package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.model.user.UserSearchCriteria;
import com.example.keycloak.multitenant.model.user.UserWithRoles;
import com.example.keycloak.multitenant.model.user.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUserService;
import java.util.Collections;
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
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Pruebas unitarias para la clase UserService, utilizando Mockito.
 * Valida la lógica de negocio y la delegación de responsabilidades a la capa
 * de servicio de bajo nivel de Keycloak.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Unit Tests for UserService")
class UserServiceTest {

    @Mock
    private KeycloakUserService keycloakUserService;
    @Mock
    private RegistrationFlowService registrationFlowService;

    @InjectMocks
    private UserService userService;

    private UserRequest userRequest;
    private String realm;

    @BeforeEach
    void setUp() {
        userRequest = new UserRequest(
                "user",
                "user@gmail.com",
                "Test",
                "User",
                "USER"
        );
        realm = "plexus";
    }

    @Test
    @DisplayName("registerUser debería crear usuario si realm existe y email no está registrado")
    void registerUser_shouldCreateUserSuccessfully() {
        when(keycloakUserService.userExistsByEmail(anyString(), anyString())).thenReturn(false);
        doNothing().when(registrationFlowService)
                .startSetPasswordFlow("plexus", null, userRequest);

        Map<String, Object> response = userService.registerUser(realm, userRequest);

        assertNotNull(response);
        assertEquals("Usuario registrado. Esperando aprobacion de administrador.", response.get("message"));
        assertEquals(realm, response.get("tenantId"));
        assertEquals(realm, response.get("keycloakRealm"));

        verify(keycloakUserService, times(1)).userExistsByEmail(eq(realm), eq(userRequest.email()));
        verify(keycloakUserService, times(1)).createUserWithRole(eq(realm), eq(userRequest), anyString());
    }

    @Test // Esta anotación estaba faltando
    @DisplayName("registerUser debería lanzar excepción si el realm no existe")
    void registerUser_shouldThrowExceptionIfRealmNotFound() {
        when(keycloakUserService.userExistsByEmail(anyString(), anyString())).thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND));

        assertThrows(ResponseStatusException.class, () -> userService.registerUser("unknownRealm", userRequest));

        verify(keycloakUserService, never()).createUserWithRole(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("registerUser debería lanzar excepción si el email ya existe")
    void registerUser_shouldThrowExceptionIfEmailExists() {
        when(keycloakUserService.userExistsByEmail(eq(realm), eq(userRequest.email()))).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> userService.registerUser(realm, userRequest));

        assertEquals("El email 'user@gmail.com' ya está registrado.", ex.getMessage());
        verify(keycloakUserService, never()).createUserWithRole(anyString(), any(), anyString());
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
        when(keycloakUserService.getAllUsersWithRoles(realm)).thenReturn(usersWithRoles);

        List<UserWithRoles> result = userService.getAllUsers(realm);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("testuser", result.get(0).username());
        assertEquals("user", result.get(0).roles().get(0));

        verify(keycloakUserService, times(1)).getAllUsersWithRoles(realm);
    }

    @Test
    @DisplayName("updateUser debería delegar en keycloakUserService")
    void updateUser_shouldDelegateTokeycloakUserService() {
        String userId = "12345";
        userService.updateUser(realm, userId, userRequest);

        verify(keycloakUserService, times(1)).updateUser(realm, userId, userRequest);
    }

    @Test
    @DisplayName("deleteUser debería delegar en keycloakUserService")
    void deleteUser_shouldDelegateTokeycloakUserService() {
        String userId = "12345";
        userService.deleteUser(realm, userId);

        verify(keycloakUserService, times(1)).deleteUser(realm, userId);
    }

    @Test
    @DisplayName("getUserById debería devolver un usuario con roles si es encontrado")
    void getUserById_shouldReturnUserWithRoles_WhenUserIsFound() {
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
        when(keycloakUserService.getUserByIdWithRoles(realm, userId)).thenReturn(mockUser);

        UserWithRoles result = userService.getUserById(realm, userId);

        assertNotNull(result);
        assertEquals(userId, result.id());
        assertEquals(mockUser.username(), result.username());
        verify(keycloakUserService, times(1)).getUserByIdWithRoles(realm, userId);
    }

    @Test
    @DisplayName("getUserByEmail debería devolver un usuario con roles si es encontrado")
    void getUserByEmail_shouldReturnUserWithRoles_WhenUserIsFound() {
        String email = "test@example.com";
        UserWithRoles mockUser = new UserWithRoles(
                UUID.randomUUID().toString(),
                "testuser",
                email,
                "Test",
                "User",
                true,
                true,
                List.of("user")
        );
        when(keycloakUserService.getUserByEmailWithRoles(realm, email)).thenReturn(mockUser);

        UserWithRoles result = userService.getUserByEmail(realm, email);

        assertNotNull(result);
        assertEquals(mockUser.email(), result.email());
        assertEquals(mockUser.username(), result.username());
        verify(keycloakUserService, times(1)).getUserByEmailWithRoles(realm, email);
    }

    @Test
    @DisplayName("getUsersByAttributes debería devolver una lista de usuarios con atributos")
    void getUsersByAttributes_shouldReturnUsersWithAttributesList() {
        UserSearchCriteria criteria = new UserSearchCriteria("Plexus", "ES", "IT");

        List<UserWithRolesAndAttributes> mockUsers = Collections.singletonList(
                new UserWithRolesAndAttributes(
                        new UserWithRoles(
                                "123",
                                "testuser",
                                "test@test.com",
                                "Test",
                                "User",
                                true,
                                true,
                                List.of("user")
                        ),
                        Map.of("organization", List.of("Plexus"))
                )
        );
        when(keycloakUserService.getUsersByAttributes(realm, criteria)).thenReturn(mockUsers);

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(realm, criteria);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(mockUsers, result);

        verify(keycloakUserService, times(1)).getUsersByAttributes(realm, criteria);
    }

    @Test
    @DisplayName("resetUserPassword debería delegar en keycloakUserService cuando la nueva contraseña es válida")
    void resetUserPassword_shouldDelegateToKeycloakService_whenNewPasswordIsValid() {
        String userId = "12345";
        String newPassword = "newValidPassword";

        userService.resetUserPassword(realm, userId, newPassword);

        verify(keycloakUserService, times(1)).resetUserPassword(realm, userId, newPassword);
    }

    @Test
    @DisplayName("resetUserPassword debería lanzar IllegalArgumentException si la nueva contraseña es nula")
    void resetUserPassword_shouldThrowIllegalArgumentException_whenNewPasswordIsNull() {
        String userId = "12345";
        String newPasswordNull = null;

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                userService.resetUserPassword(realm, userId, newPasswordNull)
        );

        assertEquals("La nueva contrasena no puede estar vacia.", ex.getMessage());
        verify(keycloakUserService, never()).resetUserPassword(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("resetUserPassword debería lanzar IllegalArgumentException si la nueva contraseña es un string vacío")
    void resetUserPassword_shouldThrowIllegalArgumentException_whenNewPasswordIsBlank() {
        String userId = "12345";
        String newPasswordBlank = "   ";

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                userService.resetUserPassword(realm, userId, newPasswordBlank)
        );

        assertEquals("La nueva contrasena no puede estar vacia.", ex.getMessage());
        verify(keycloakUserService, never()).resetUserPassword(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("resetUserPassword debería propagar la excepción de KeycloakUserService")
    void resetUserPassword_shouldPropagateException_whenKeycloakServiceThrows() {
        String userId = "12345";
        String newPassword = "newPassword";
        ResponseStatusException delegatedException = new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado.");

        doThrow(delegatedException).when(keycloakUserService).resetUserPassword(realm, userId, newPassword);

        ResponseStatusException thrown = assertThrows(ResponseStatusException.class, () ->
                userService.resetUserPassword(realm, userId, newPassword)
        );

        assertEquals(delegatedException, thrown);
    }
}
