package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakUserCreationException;
import com.example.keycloak.multitenant.model.UserRequest;
import com.example.keycloak.multitenant.model.UserSearchCriteria;
import com.example.keycloak.multitenant.model.UserWithRoles;
import com.example.keycloak.multitenant.model.UserWithRolesAndAttributes;
import com.example.keycloak.multitenant.service.utils.KeycloakAdminService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    @DisplayName("Debería obtener un usuario con sus roles por ID")
    void getUserByIdWithRoles_Success() {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setId(testUserId);
        userRep.setUsername("testuser");
        userRep.setFirstName("Test");
        userRep.setLastName("User");
        userRep.setEmail("test@example.com");
        userRep.setEnabled(true);
        userRep.setEmailVerified(true);

        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName("admin");

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.get(testUserId)).thenReturn(userResource);
        when(userResource.toRepresentation()).thenReturn(userRep);
        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(roleRep));

        UserWithRoles result = userService.getUserByIdWithRoles(testRealm, testUserId);

        assertEquals(testUserId, result.id());
        assertEquals("testuser", result.username());
        assertEquals("test@example.com", result.email());
        assertEquals("Test", result.firstName());
        assertEquals("User", result.lastName());
        assertEquals(true, result.enabled());
        assertEquals(true, result.emailVerified());
        assertEquals(1, result.roles().size());
        assertEquals("admin", result.roles().get(0));

        verify(usersResource, times(2)).get(testUserId);
    }

    @Test
    @DisplayName("Debería obtener todos los usuarios con sus roles")
    void getAllUsersWithRoles_Success() {
        UserRepresentation userRep1 = new UserRepresentation();
        userRep1.setId("user1-id");
        userRep1.setUsername("user1");
        userRep1.setEnabled(true);
        userRep1.setEmailVerified(true);
        UserRepresentation userRep2 = new UserRepresentation();
        userRep2.setId("user2-id");
        userRep2.setUsername("user2");
        userRep2.setEnabled(true);
        userRep2.setEmailVerified(false);

        RoleRepresentation roleRep1 = new RoleRepresentation();
        roleRep1.setName("user");
        RoleRepresentation roleRep2 = new RoleRepresentation();
        roleRep2.setName("user");

        UserResource userResource1 = mock(UserResource.class);
        UserResource userResource2 = mock(UserResource.class);

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(userRep1, userRep2));
        when(usersResource.get("user1-id")).thenReturn(userResource1);
        when(usersResource.get("user2-id")).thenReturn(userResource2);

        when(userResource1.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(roleRep1));

        when(userResource2.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(roleRep2));

        List<UserWithRoles> result = userService.getAllUsersWithRoles(testRealm);

        assertEquals("user1", result.get(0).username());
        assertEquals(1, result.get(0).roles().size());
        assertEquals("user", result.get(0).roles().get(0));
        assertEquals(true, result.get(0).enabled());
        assertEquals(true, result.get(0).emailVerified());

        assertEquals("user2", result.get(1).username());
        assertEquals(1, result.get(1).roles().size());
        assertEquals("user", result.get(1).roles().get(0));
        assertEquals(true, result.get(1).enabled());
        assertEquals(false, result.get(1).emailVerified());

        verify(usersResource, times(1)).list();
        verify(usersResource, times(2)).get(anyString());
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
    @DisplayName("Debería lanzar WebApplicationException si la obtención de usuarios falla")
    void obtenerUsuariosDelRealm_Failure() {
        when(realmResource.users()).thenThrow(new WebApplicationException("Error al obtener usuarios", Response.Status.INTERNAL_SERVER_ERROR));
        WebApplicationException exception = assertThrows(WebApplicationException.class, () ->
                userService.getAllUsersWithRoles("testRealm")
        );
        assertTrue(exception.getMessage().contains("Error al obtener usuarios"));
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

    @Test
    @DisplayName("Debería obtener un usuario por email con sus roles")
    void getUserByEmailWithRoles_Success() {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setId("user-id-1");
        userRep.setUsername("testuser");
        userRep.setEmail("test@example.com");
        userRep.setFirstName("Test");
        userRep.setLastName("User");
        userRep.setEnabled(true);
        userRep.setEmailVerified(true);

        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName("user");

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.searchByEmail("test@example.com", true)).thenReturn(List.of(userRep));
        when(usersResource.get(userRep.getId())).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(roleRep));

        UserWithRoles result = userService.getUserByEmailWithRoles(testRealm, "test@example.com");

        assertEquals("user-id-1", result.id());
        assertEquals("test@example.com", result.email());
        assertEquals("testuser", result.username());
        assertEquals(true, result.enabled());
        assertEquals(true, result.emailVerified());
        assertEquals(1, result.roles().size());
        assertEquals("user", result.roles().get(0));
    }

    @Test
    @DisplayName("Debería lanzar NotFoundException si el usuario no es encontrado por email")
    void getUserByEmailWithRoles_NotFound() {
        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.searchByEmail("nonexistent@example.com", true)).thenReturn(Collections.emptyList());

        assertThrows(NotFoundException.class, () ->
                userService.getUserByEmailWithRoles(testRealm, "nonexistent@example.com")
        );
    }

    @Test
    @DisplayName("Debería retornar usuarios que coinciden con todos los criterios de busqueda")
    void getUsersByAttributes_shouldReturnUsersMatchingAllCriteria() {
        UserSearchCriteria criteria = new UserSearchCriteria("Plexus", "ES", "IT");

        UserRepresentation matchingUser = createUserRepresentation("user-123", "matchinguser",
                Map.of("organization", List.of("Plexus"), "subsidiary", List.of("ES"), "department", List.of("IT")));

        UserRepresentation nonMatchingUser = createUserRepresentation("user-456", "nonmatchinguser",
                Map.of("organization", List.of("AnotherOrg")));

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(matchingUser, nonMatchingUser));

        UserResource userResourceMock = mock(UserResource.class);
        when(usersResource.get("user-123")).thenReturn(userResourceMock);
        when(userResourceMock.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(createRole("admin_role")));

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(testRealm, criteria);

        assertNotNull(result);
        assertEquals(1, result.size());

        UserWithRolesAndAttributes foundUser = result.get(0);
        assertEquals("user-123", foundUser.userWithRoles().id());
        assertEquals("matchinguser", foundUser.userWithRoles().username());
        assertEquals("Plexus", foundUser.attributes().get("organization").get(0));
        assertEquals("ES", foundUser.attributes().get("subsidiary").get(0));
        assertEquals("IT", foundUser.attributes().get("department").get(0));
        assertTrue(foundUser.userWithRoles().roles().contains("admin_role"));

        verify(usersResource, times(1)).list();
        verify(usersResource, times(1)).get("user-123");
    }

    // Métodos auxiliares
    private UserRepresentation createUserRepresentation(String id, String username, Map<String, List<String>> attributes) {
        UserRepresentation user = new UserRepresentation();
        user.setId(id);
        user.setUsername(username);
        user.setAttributes(attributes);
        user.setEnabled(true);
        user.setEmailVerified(true);
        return user;
    }

    private RoleRepresentation createRole(String name) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(name);
        return role;
    }

    @Test
    @DisplayName("getUsersByAttributes debería manejar errores al obtener roles y continuar con la busqueda")
    void getUsersByAttributes_shouldHandleRoleFetchingError() {
        UserSearchCriteria criteria = new UserSearchCriteria(null, null, null);

        UserRepresentation matchingUser1 = createUserRepresentation("user-1", "user1", Collections.emptyMap());

        UserRepresentation failingUser = createUserRepresentation("user-2", "user2", Collections.emptyMap());

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(matchingUser1, failingUser));

        UserResource userResource1 = mock(UserResource.class);
        when(usersResource.get("user-1")).thenReturn(userResource1);
        when(userResource1.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(createRole("user")));

        UserResource userResource2 = mock(UserResource.class);
        when(usersResource.get("user-2")).thenReturn(userResource2);
        when(userResource2.roles()).thenThrow(new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()));

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(testRealm, criteria);

        assertNotNull(result);

        assertEquals(2, result.size());
        assertEquals("user1", result.get(0).userWithRoles().username());
        assertTrue(result.get(0).userWithRoles().roles().contains("user"));

        verify(usersResource, times(1)).list();
        verify(usersResource, times(1)).get("user-1");
        verify(usersResource, times(1)).get("user-2");
    }

    @Test
    @DisplayName("getUsersByAttributes debería retornar todos los usuarios si los criterios de busqueda son nulos")
    void getUsersByAttributes_shouldReturnAllUsersIfCriteriaIsNull() {
        UserRepresentation user1 = createUserRepresentation("user-1", "user1", Map.of("organization", List.of("Plexus")));
        UserRepresentation user2 = createUserRepresentation("user-2", "user2", Map.of("subsidiary", List.of("ES")));

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(user1, user2));

        UserResource userResource1 = mock(UserResource.class);
        UserResource userResource2 = mock(UserResource.class);
        when(usersResource.get("user-1")).thenReturn(userResource1);
        when(usersResource.get("user-2")).thenReturn(userResource2);

        when(userResource1.roles()).thenReturn(roleMappingResource);
        when(userResource2.roles()).thenReturn(roleMappingResource);

        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(createRole("user")));

        UserSearchCriteria criteria = new UserSearchCriteria(null, null, null);

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(testRealm, criteria);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("user1", result.get(0).userWithRoles().username());
        assertEquals("user2", result.get(1).userWithRoles().username());

        verify(usersResource, times(1)).list();
        verify(usersResource, times(1)).get("user-1");
        verify(usersResource, times(1)).get("user-2");
    }

    @Test
    @DisplayName("getUsersByAttributes debería filtrar usuarios sin atributos si se proporcionan criterios")
    void getUsersByAttributes_shouldFilterUsersWithNoAttributes() {
        UserRepresentation userWithAttributes = createUserRepresentation("user-1", "user1", Map.of("organization", List.of("Plexus")));
        UserRepresentation userWithoutAttributes = new UserRepresentation();
        userWithoutAttributes.setId("user-2");
        userWithoutAttributes.setUsername("user2");
        userWithoutAttributes.setAttributes(null);

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(userWithAttributes, userWithoutAttributes));

        UserResource userResource1 = mock(UserResource.class);
        when(usersResource.get("user-1")).thenReturn(userResource1);
        when(userResource1.roles()).thenReturn(roleMappingResource);
        when(roleMappingResource.realmLevel()).thenReturn(roleScopeResource);
        when(roleScopeResource.listAll()).thenReturn(List.of(createRole("user")));

        UserSearchCriteria criteria = new UserSearchCriteria("Plexus", null, null);

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(testRealm, criteria);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("user1", result.get(0).userWithRoles().username());

        verify(usersResource, times(1)).list();
        verify(usersResource, times(1)).get("user-1");
        verify(usersResource, times(0)).get("user-2");
    }

    @Test
    @DisplayName("getUsersByAttributes debería filtrar usuarios si el atributo de filial no coincide")
    void getUsersByAttributes_shouldFilterBySubsidiaryMismatch() {
        UserRepresentation userWithWrongSubsidiary = createUserRepresentation("user-1", "user1",
                Map.of("organization", List.of("Plexus"), "subsidiary", List.of("UK")));

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(userWithWrongSubsidiary));

        UserSearchCriteria criteria = new UserSearchCriteria("Plexus", "ES", null);

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(testRealm, criteria);

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(usersResource, times(1)).list();
        verify(usersResource, times(0)).get(any());
    }

    @Test
    @DisplayName("getUsersByAttributes debería filtrar usuarios si el atributo de departamento no coincide")
    void getUsersByAttributes_shouldFilterByDepartmentMismatch() {
        UserRepresentation userWithWrongDepartment = createUserRepresentation("user-1", "user1",
                Map.of("organization", List.of("Plexus"), "department", List.of("HR")));

        when(realmResource.users()).thenReturn(usersResource);
        when(usersResource.list()).thenReturn(List.of(userWithWrongDepartment));

        UserSearchCriteria criteria = new UserSearchCriteria("Plexus", null, "IT");

        List<UserWithRolesAndAttributes> result = userService.getUsersByAttributes(testRealm, criteria);

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(usersResource, times(1)).list();
        verify(usersResource, times(0)).get(any());
    }
}