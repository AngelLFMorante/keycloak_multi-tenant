package com.example.keycloakdemo.service;

import com.example.keycloakdemo.exception.KeycloakUserCreationException;
import com.example.keycloakdemo.model.RegisterRequest;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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

    @InjectMocks
    private KeycloakService keycloakService;

    private String testRealm = "test-realm";
    private String testEmail = "test@example.com";
    private String testUsername = "testuser";
    private String testPassword = "password123";
    private String testUserId = "some-user-id";

    @BeforeEach
    void setUp() {
        when(keycloak.realm(anyString())).thenReturn(realmResource);
        when(realmResource.users()).thenReturn(usersResource);
    }

    @Test
    @DisplayName("Debería crear un usuario exitosamente en Keycloak")
    void createUser_Success() {
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
        when(usersResource.searchByEmail(testEmail, true))
                .thenReturn(Collections.emptyList());

        assertFalse(keycloakService.userExistsByEmail(testRealm, testEmail));

        verify(keycloak, times(1)).realm(testRealm);
        verify(realmResource, times(1)).users();
        verify(usersResource, times(1)).searchByEmail(testEmail, true);
    }
}
