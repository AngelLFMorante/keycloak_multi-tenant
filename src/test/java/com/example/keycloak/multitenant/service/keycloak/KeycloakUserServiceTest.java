package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    private UserRequest userRequest;

    private final String testRealm = "testRealm";
    private final String testUserId = "123";
    private final String testRole = "ADMIN_ROLE";
    private final String testEmail = "test@example.com";
    private final String testUsername = "testuser";
    private final String tempPassword = "12345678";

    @BeforeEach
    void setUp() {
        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        userRequest = new UserRequest(
                testUsername,
                testEmail,
                "Test",
                "User",
                testRole
        );
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
        when(response.getStatusInfo()).thenReturn(Response.Status.CREATED);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/" + testUserId));

        doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get("ADMIN_ROLE")).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRepresentation);

        when(realmResource.users().get(testUserId)).thenReturn(userResource);
        when(realmResource.users().get(testUserId).roles()).thenReturn(roleMappingResource);
        when(realmResource.users().get(testUserId).roles().realmLevel()).thenReturn(roleScopeResource);

        assertDoesNotThrow(() -> userService.createUserWithRole(testRealm, "plexus", userRequest, tempPassword));

        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(1)).getStatus();
        verify(response, times(1)).getLocation();
        verify(realmResource.users(), times(4)).get(testUserId);
        verify(userResource, times(1)).resetPassword(any(CredentialRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si la creación de usuario falla")
    void createUserWithRole_Failure() {
        when(realmResource.users()).thenReturn(usersResource);

        Response response = mock(Response.class);
        when(response.getStatusInfo()).thenReturn(Response.Status.CREATED);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(409);
        when(response.readEntity(String.class)).thenReturn("User exists");

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                userService.createUserWithRole(testRealm, "realm", userRequest, "tempPass")
        );

        assertTrue(exception.getMessage().contains("409"));
    }

    @Test
    @DisplayName("Debería lanzar excepción si falla al asignar rol")
    void createUserWithRole_AssignRoleFailure() {
        when(realmResource.users()).thenReturn(usersResource);

        Response response = mock(Response.class);

        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatusInfo()).thenReturn(Response.Status.CREATED);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("/users/" + testUserId));

        when(usersResource.get(testUserId)).thenReturn(userResource);
        doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenThrow(new NotFoundException("Role not found"));

        assertThrows(KeycloakUserCreationException.class, () ->
                userService.createUserWithRole(testRealm, "plexus", userRequest, "tempPass")
        );
    }

    @Test
    @DisplayName("Debería actualizar usuario exitosamente")
    void updateUser_Success() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get(testUserId)).thenReturn(userResource);
        UserRepresentation existingUser = new UserRepresentation();
        when(userResource.toRepresentation()).thenReturn(existingUser);

        assertDoesNotThrow(() -> userService.updateUser(testRealm, testUserId, userRequest));

        verify(userResource, times(1)).update(any(UserRepresentation.class));
    }

    @Test
    @DisplayName("Debería actualizar el apellido y el email de un usuario")
    void updateUser_ShouldUpdateLastNameAndEmail() {
        RealmResource realmResourceMock = mock(RealmResource.class);
        UserResource userResourceMock = mock(UserResource.class);
        UserRepresentation userRepresentationMock = mock(UserRepresentation.class);

        UserRequest userUpdate = new UserRequest(
                "username",
                "updated@example.com",
                "UpdatedFirst",
                "UpdatedLast",
                "ROLE"
        );

        when(utilsService.getRealmResource(testRealm)).thenReturn(realmResourceMock);
        when(realmResourceMock.users()).thenReturn(usersResource);
        when(usersResource.get(testUserId)).thenReturn(userResourceMock);
        when(userResourceMock.toRepresentation()).thenReturn(userRepresentationMock);

        userService.updateUser(testRealm, testUserId, userUpdate);

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

    @Test
    @DisplayName("Debería lanzar RuntimeException si la obtención de usuarios falla")
    void obtenerUsuariosDelRealm_Failure() {
        when(realmResource.users()).thenThrow(new WebApplicationException("Error al obtener usuarios", Response.Status.INTERNAL_SERVER_ERROR));

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                userService.getAllUsers("testRealm")
        );

        assertTrue(exception.getMessage().contains("Error al obtener usuarios del realm"));
    }

    @Test
    @DisplayName("Debería lanzar NotFoundException si el usuario no es encontrado para actualización")
    void actualizarUsuario_NotFound() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get("123")).thenThrow(new NotFoundException("Usuario no encontrado"));

        NotFoundException exception = assertThrows(NotFoundException.class, () ->
                userService.updateUser("plexus", "123", userRequest)
        );

        assertTrue(exception.getMessage().contains("Usuario no encontrado con ID"));
    }

    @Test
    @DisplayName("Debería lanzar KeycloakUserCreationException si la actualización del usuario falla")
    void actualizarUsuario_Failure() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get("123")).thenThrow(new WebApplicationException("Error al actualizar usuario", Response.Status.BAD_REQUEST));

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                userService.updateUser("plexus", "123", userRequest)
        );

        assertTrue(exception.getMessage().contains("Error al actualizar el usuario"));
    }

    @Test
    @DisplayName("Debería lanzar NotFoundException si el usuario no es encontrado para eliminar")
    void eliminarUsuario_NotFound() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get("123")).thenThrow(new NotFoundException("Usuario no encontrado"));

        NotFoundException exception = assertThrows(NotFoundException.class, () ->
                userService.deleteUser("plexus", "123")
        );

        assertTrue(exception.getMessage().contains("Usuario no encontrado con ID"));
    }

    @Test
    @DisplayName("Debería lanzar KeycloakUserCreationException si la eliminación del usuario falla")
    void eliminarUsuario_Failure() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get("123")).thenThrow(new WebApplicationException("Error al eliminar usuario", Response.Status.BAD_REQUEST));

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                userService.deleteUser("plexus", "123")
        );

        assertTrue(exception.getMessage().contains("Error al eliminar el usuario"));
    }

    @Test
    @DisplayName("Debería lanzar KeycloakUserCreationException si el usuario ya existe")
    void crearUsuario_Conflict() {
        when(realmResource.users()).thenReturn(usersResource);
        Response response = mock(Response.class);
        when(response.getStatusInfo()).thenReturn(Response.Status.CONFLICT);
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);

        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                userService.createUserWithRole(testRealm, "plexus", userRequest, tempPassword)
        );

        assertTrue(exception.getMessage().contains("El nombre de usuario o email ya existen"));
    }

}