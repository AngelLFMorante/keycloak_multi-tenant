package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.model.RegisterRequest;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Clase de test unitario para {@link KeycloakService} utilizando Mockito.
 * Se enfoca en probar la lógica de negocio de KeycloakService aislando las llamadas
 * a la API de Keycloak mediante mocks.
 */
@ExtendWith(MockitoExtension.class)
class KeycloakServiceTest {

    @Mock
    private Keycloak keycloak;

    @Mock
    private RealmResource realmResource;

    @Mock
    private UsersResource usersResource;

    @Mock
    private UserResource userResource;

    @Mock
    private Response response;

    @Mock
    private RolesResource rolesResource;

    @InjectMocks
    private KeycloakService keycloakService;

    private String testRealm = "test-realm";
    private String testEmail = "test@example.com";
    private String testUsername = "testuser";
    private String testPassword = "password123";
    private String testUserId = "some-user-id";

    private String testRoleName = "TEST_ROLE";
    private String testRoleDescription = "Descripción del rol de prueba";

    @BeforeEach
    void setUp() {
        when(keycloak.realm(anyString())).thenReturn(realmResource);
    }

    @Test
    @DisplayName("Debería crear un usuario exitosamente en Keycloak")
    void createUser_Success() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/" + testUserId));
        when(realmResource.users().get(testUserId)).thenReturn(userResource);

        doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(testUsername);
        registerRequest.setEmail(testEmail);
        registerRequest.setPassword(testPassword);
        registerRequest.setConfirmPassword(testPassword);
        registerRequest.setFirstName("Test");
        registerRequest.setLastName("User");

        assertDoesNotThrow(() -> keycloakService.createUser(testRealm, registerRequest));

        verify(keycloak, times(1)).realm(testRealm);
        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(1)).getStatus();
        verify(response, times(1)).getLocation();
        verify(realmResource.users(), times(1)).get(testUserId);
        verify(userResource, times(1)).resetPassword(any(CredentialRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si la creación de usuario falla con un estado no 201")
    void createUser_FailureStatus() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(409);
        when(response.readEntity(String.class)).thenReturn("User with username already exists");

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(testUsername);
        registerRequest.setEmail(testEmail);
        registerRequest.setPassword(testPassword);
        registerRequest.setConfirmPassword(testPassword);
        registerRequest.setFirstName("Test");
        registerRequest.setLastName("User");

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                keycloakService.createUser(testRealm, registerRequest));

        assertTrue(exception.getMessage().contains("Error al crear usuario en Keycloak. Estado HTTP: 409."));
        assertTrue(exception.getMessage().contains("User with username already exists"));

        verify(keycloak, times(1)).realm(testRealm);
        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(3)).getStatus();
        verify(response, times(1)).readEntity(String.class);
        verify(realmResource.users(), never()).get(anyString());
        verify(userResource, never()).resetPassword(any(CredentialRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si falla el establecimiento de contraseña")
    void createUser_PasswordResetFailure() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/" + testUserId));
        when(realmResource.users().get(testUserId)).thenReturn(userResource);

        doThrow(new RuntimeException("Keycloak API error during password reset"))
                .when(userResource).resetPassword(any(CredentialRepresentation.class));

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(testUsername);
        registerRequest.setEmail(testEmail);
        registerRequest.setPassword(testPassword);
        registerRequest.setConfirmPassword(testPassword);
        registerRequest.setFirstName("Test");
        registerRequest.setLastName("User");

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                keycloakService.createUser(testRealm, registerRequest));

        assertTrue(exception.getMessage().contains("Error al establecer la contraseña para el usuario"));
        assertTrue(exception.getMessage().contains("Keycloak API error during password reset"));

        verify(keycloak, times(1)).realm(testRealm);
        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(1)).getStatus();
        verify(response, times(1)).getLocation();
        verify(realmResource.users(), times(1)).get(testUserId);
        verify(userResource, times(1)).resetPassword(any(CredentialRepresentation.class));
    }


    @Test
    @DisplayName("Debería retornar true si el email ya existe en Keycloak")
    void userExistsByEmail_EmailExists() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.searchByEmail(testEmail, true))
                .thenReturn(Collections.singletonList(new UserRepresentation()));

        assertTrue(keycloakService.userExistsByEmail(testRealm, testEmail));

        verify(keycloak, times(1)).realm(testRealm);
        verify(realmResource, times(1)).users();
        verify(usersResource, times(1)).searchByEmail(testEmail, true);
    }

    @Test
    @DisplayName("Debería retornar false si el email no existe en Keycloak")
    void userExistsByEmail_EmailDoesNotExist() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.searchByEmail(testEmail, true))
                .thenReturn(Collections.emptyList());

        assertFalse(keycloakService.userExistsByEmail(testRealm, testEmail));

        verify(keycloak, times(1)).realm(testRealm);
        verify(realmResource, times(1)).users();
        verify(usersResource, times(1)).searchByEmail(testEmail, true);
    }

    @Test
    @DisplayName("Debería crear un rol exitosamente en Keycloak cuando no existe")
    void createRole_SuccessWhenNotExists() {
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.emptyList());
        doNothing().when(rolesResource).create(any(RoleRepresentation.class));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRoleName);
        request.setDescription(testRoleDescription);

        keycloakService.createRole(testRealm, request);

        verify(rolesResource, times(1)).list();
        verify(rolesResource, times(1)).create(argThat(role ->
                role.getName().equals(testRoleName) &&
                        role.getDescription().equals(testRoleDescription) &&
                        !role.getClientRole() // Debe ser un rol de realm
        ));
    }

    @Test
    @DisplayName("Debería lanzar KeycloakRoleCreationException si el rol ya existe")
    void createRole_ThrowsExceptionIfRoleExists() {
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(testRoleName);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.singletonList(existingRole));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRoleName);
        request.setDescription(testRoleDescription);

        KeycloakRoleCreationException thrown = assertThrows(KeycloakRoleCreationException.class, () ->
                keycloakService.createRole(testRealm, request)
        );

        assertTrue(thrown.getMessage().contains("El rol '" + testRoleName + "' ya existe en el realm '" + testRealm + "'."));
        verify(rolesResource, never()).create(any(RoleRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar KeycloakRoleCreationException si la creación de rol falla con WebApplicationException")
    void createRole_ThrowsExceptionOnWebApplicationError() {
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.emptyList());

        WebApplicationException webAppException = new WebApplicationException(Response.status(400).entity("Invalid role data").build());
        doThrow(webAppException).when(rolesResource).create(any(RoleRepresentation.class));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRoleName);
        request.setDescription(testRoleDescription);

        KeycloakRoleCreationException thrown = assertThrows(KeycloakRoleCreationException.class, () ->
                keycloakService.createRole(testRealm, request)
        );

        assertTrue(thrown.getMessage().contains("Error al crear el rol en Keycloak. Estado HTTP: 400. Detalles: Invalid role data"));
        verify(rolesResource, times(1)).list();
        verify(rolesResource, times(1)).create(any(RoleRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si la creación de rol falla por excepción genérica")
    void createRole_ThrowsRuntimeExceptionOnGenericError() {
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.emptyList());

        doThrow(new RuntimeException("Network error")).when(rolesResource).create(any(RoleRepresentation.class));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRoleName);
        request.setDescription(testRoleDescription);

        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                keycloakService.createRole(testRealm, request)
        );

        assertTrue(thrown.getMessage().contains("Error inesperado al crear el rol: Network error"));
        verify(rolesResource, times(1)).list();
        verify(rolesResource, times(1)).create(any(RoleRepresentation.class));
    }

    @Test
    @DisplayName("Debería eliminar un rol exitosamente cuando existe")
    void deleteRole_SuccessWhenExists() {
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(testRoleName);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.singletonList(existingRole));

        doNothing().when(rolesResource).deleteRole(anyString());

        assertDoesNotThrow(() -> keycloakService.deleteRole(testRealm, testRoleName));

        verify(rolesResource, times(1)).list();
        verify(rolesResource, times(1)).deleteRole(testRoleName);
    }

    @Test
    @DisplayName("Debería lanzar NotFoundException si el rol a eliminar no existe")
    void deleteRole_ThrowsNotFoundExceptionIfRoleDoesNotExist() {
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.emptyList());

        NotFoundException thrown = assertThrows(NotFoundException.class, () ->
                keycloakService.deleteRole(testRealm, testRoleName)
        );

        assertTrue(thrown.getMessage().contains("Rol '" + testRoleName + "' no encontrado en el realm '" + testRealm + "'."));
        verify(rolesResource, times(1)).list();
        verify(rolesResource, never()).deleteRole(anyString());
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si la eliminación de rol falla por excepción genérica")
    void deleteRole_ThrowsRuntimeExceptionOnGenericError() {
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(testRoleName);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.singletonList(existingRole));

        doThrow(new RuntimeException("Keycloak internal error during deletion")).when(rolesResource).deleteRole(anyString());

        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                keycloakService.deleteRole(testRealm, testRoleName)
        );

        assertTrue(thrown.getMessage().contains("Error inesperado al eliminar el rol: Keycloak internal error during deletion"));
        verify(rolesResource, times(1)).list();
        verify(rolesResource, times(1)).deleteRole(testRoleName);
    }

    @Test
    @DisplayName("Debería obtener roles exitosamente")
    void testGetRolesSuccess() {
        RoleRepresentation role1 = new RoleRepresentation();
        role1.setName("role1");
        role1.setId("id1");
        RoleRepresentation role2 = new RoleRepresentation();
        role2.setName("role2");
        role2.setId("id2");
        List<RoleRepresentation> mockRoles = Arrays.asList(role1, role2);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(mockRoles);

        List<RoleRepresentation> resultRoles = keycloakService.getRoles(testRealm);

        assertNotNull(resultRoles);
        assertEquals(2, resultRoles.size());
        assertTrue(resultRoles.stream().anyMatch(r -> r.getName().equals("role1")));
        assertTrue(resultRoles.stream().anyMatch(r -> r.getName().equals("role2")));

        verify(rolesResource, times(1)).list();
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si la obtención de roles falla")
    void testGetRolesFailure() {
        when(realmResource.roles()).thenReturn(rolesResource);
        doThrow(new RuntimeException("Keycloak API error")).when(rolesResource).list();

        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                keycloakService.getRoles(testRealm)
        );

        assertTrue(thrown.getMessage().contains("Error inesperado al obtener roles"));
        verify(rolesResource, times(1)).list();
    }
}
