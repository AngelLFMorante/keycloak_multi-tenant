package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
/*
@ExtendWith(MockitoExtension.class)
class KeycloakUserServiceTest {

    @Mock
    private KeycloakRoleService keycloakRoleService;

    @Mock
    private KeycloakAdminService utilsService;

    @Mock
    private RealmResource realmResource;

    @Mock
    private UsersResource usersResource;

    @Mock
    private UserResource userResource;

    @Mock
    private RolesResource rolesResource;

    @Mock
    private RoleResource roleResource;

    @Mock
    private RoleMappingResource roleMappingResource;

    @Mock
    private RoleScopeResource roleScopeResource;

    @Mock
    private Response response;

    @Mock
    private RoleRepresentation roleRepresentation;

    @InjectMocks
    private KeycloakUserService userService;

    private final String testRealm = "testRealm";
    private final String testUserId = "123";
    private final String testRole = "ADMIN_ROLE";
    private final String testEmail = "test@example.com";
    private final String testUsername = "testuser";
    private final String tempPassword = "12345678";

    @BeforeEach
    void setUp() {
        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
    }

    @Test
    @DisplayName("Debería obtener todos los usuarios del realm")
    void getAllUsers_Success() {
        UserRepresentation user1 = new UserRepresentation();
        user1.setUsername("user1");
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(user1));

        List<UserRepresentation> result = userService.getAllUsers(testRealm);

        assertEquals(1, result.size());
        verify(usersResource, times(1)).list();
    }

    @Test
    @DisplayName("Debería comprobar si existe un usuario por email")
    void userExistsByEmail_Success() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.searchByEmail("test@example.com", true))
                .thenReturn(List.of(new UserRepresentation()));

        assertTrue(userService.userExistsByEmail(testRealm, "test@example.com"));
    }

    @Test
    @DisplayName("Debería crear un usuario exitosamente en Keycloak")
    void createUser_Success() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/" + testUserId));

        doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

        UserRequest userRequest = new UserRequest();
        userRequest.setUsername(testUsername);
        userRequest.setEmail(testEmail);
        userRequest.setFirstName("Test");
        userRequest.setLastName("User");
        userRequest.setRole("ROLE");

        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get("ROLE")).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRepresentation);

        when(realmResource.users().get(testUserId)).thenReturn(userResource);
        when(realmResource.users().get(testUserId).roles()).thenReturn(roleMappingResource);
        when(realmResource.users().get(testUserId).roles().realmLevel()).thenReturn(roleScopeResource);

        assertDoesNotThrow(() -> userService.createUserWithRole(testRealm, userRequest, tempPassword));

        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(1)).getStatus();
        verify(response, times(1)).getLocation();
        verify(realmResource.users(), times(4)).get(testUserId);
        verify(userResource, times(1)).resetPassword(any(CredentialRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si la creación de usuario falla")
    void createUserWithRole_Failure() {
        UserRequest request = new UserRequest();
        request.setUsername("testUser");
        request.setEmail("test@example.com");

        when(realmResource.users()).thenReturn(usersResource);

        Response response = mock(Response.class);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(409);
        when(response.readEntity(String.class)).thenReturn("User exists");

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                userService.createUserWithRole(testRealm, request, "tempPass")
        );

        assertTrue(exception.getMessage().contains("409"));
    }

    @Test
    @DisplayName("Debería lanzar excepción si falla al asignar rol")
    void createUserWithRole_AssignRoleFailure() {
        UserRequest request = new UserRequest();
        request.setUsername("testUser");
        request.setEmail("test@example.com");
        request.setRole(testRole);

        when(realmResource.users()).thenReturn(usersResource);

        Response response = mock(Response.class);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("/users/" + testUserId));

        when(usersResource.get(testUserId)).thenReturn(userResource);
        doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenThrow(new NotFoundException("Role not found"));

        assertThrows(KeycloakRoleCreationException.class, () ->
                userService.createUserWithRole(testRealm, request, "tempPass")
        );
    }

    @Test
    @DisplayName("Debería actualizar usuario exitosamente")
    void updateUser_Success() {
        UserRequest updateRequest = new UserRequest();
        updateRequest.setFirstName("NewName");

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get(testUserId)).thenReturn(userResource);
        UserRepresentation existingUser = new UserRepresentation();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        assertDoesNotThrow(() -> userService.updateUser(testRealm, testUserId, updateRequest));

        verify(userResource, times(1)).update(any(UserRepresentation.class));
    }

    @Test
    @DisplayName("Debería actualizar el apellido y el email de un usuario")
    void updateUser_ShouldUpdateLastNameAndEmail() {
        UserRequest updatedUserRequest = new UserRequest();
        updatedUserRequest.setFirstName("UpdatedFirst"); // opcional
        updatedUserRequest.setLastName("UpdatedLast");
        updatedUserRequest.setEmail("updated@example.com");

        RealmResource realmResourceMock = mock(RealmResource.class);
        UserResource userResourceMock = mock(UserResource.class);
        UserRepresentation userRepresentationMock = mock(UserRepresentation.class);

        when(utilsService.getRealmResource(testRealm)).thenReturn(realmResourceMock);
        when(realmResourceMock.users()).thenReturn(usersResource);
        when(usersResource.get(testUserId)).thenReturn(userResourceMock);
        when(userResourceMock.toRepresentation()).thenReturn(userRepresentationMock);

        userService.updateUser(testRealm, testUserId, updatedUserRequest);

        verify(userRepresentationMock).setFirstName("UpdatedFirst");
        verify(userRepresentationMock).setLastName("UpdatedLast");
        verify(userRepresentationMock).setEmail("updated@example.com");

        verify(userResourceMock).update(userRepresentationMock);
    }


    @Test
    @DisplayName("Debería eliminar usuario exitosamente")
    void deleteUser_Success() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get(testUserId)).thenReturn(userResource);
        doNothing().when(userResource).remove();

        assertDoesNotThrow(() -> userService.deleteUser(testRealm, testUserId));
        verify(userResource, times(1)).remove();
    }
}
*/