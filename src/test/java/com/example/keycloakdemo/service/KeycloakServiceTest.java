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
@ExtendWith(MockitoExtension.class) // Habilita la integración de Mockito con JUnit 5
class KeycloakServiceTest {

    @Mock // Crea un mock de la instancia de Keycloak Admin Client
    private Keycloak keycloak;

    @Mock // Crea un mock del recurso de Realm (para operaciones a nivel de realm)
    private RealmResource realmResource;

    @Mock // Crea un mock del recurso de Usuarios (para operaciones de usuarios)
    private UsersResource usersResource;

    @Mock // Crea un mock de un recurso de Usuario específico (para operaciones sobre un usuario por ID)
    private UserResource userResource;

    @Mock // Crea un mock para la respuesta de la API de Keycloak (ej. al crear un usuario)
    private Response response;

    @InjectMocks // Inyecta los mocks creados en una instancia real de KeycloakService
    private KeycloakService keycloakService;

    private String testRealm = "test-realm";
    private String testEmail = "test@example.com";
    private String testUsername = "testuser";
    private String testPassword = "password123";
    private String testUserId = "some-user-id";

    @BeforeEach
    void setUp() {
        // Configura el comportamiento de los mocks para las llamadas encadenadas
        // Esto simula la navegación a través de la API de Keycloak: keycloak.realm(realmName).users()
        when(keycloak.realm(anyString())).thenReturn(realmResource);
        when(realmResource.users()).thenReturn(usersResource);
    }

    @Test
    @DisplayName("Debería crear un usuario exitosamente en Keycloak")
    void createUser_Success() {
        // 1. Configurar el comportamiento del mock para la creación de usuario
        // Cuando usersResource.create(any(UserRepresentation.class)) es llamado,
        // debe devolver el mock 'response'.
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);

        // 2. Configurar el comportamiento del mock para la respuesta de creación
        // Cuando response.getStatus() es llamado, debe devolver 201 (Created).
        when(response.getStatus()).thenReturn(201);
        // Cuando response.getLocation() es llamado, debe devolver una URI simulada
        // que contenga el ID del usuario.
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/" + testUserId));

        // 3. Configurar el comportamiento del mock para el establecimiento de contraseña
        // Cuando realmResource.users().get(userId) es llamado, debe devolver userResource.
        when(realmResource.users().get(testUserId)).thenReturn(userResource);
        // Verificar que resetPassword es llamado con cualquier CredentialRepresentation.
        doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

        // Crear una solicitud de registro de prueba
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(testUsername);
        registerRequest.setEmail(testEmail);
        registerRequest.setPassword(testPassword);
        registerRequest.setConfirmPassword(testPassword); // Necesario para la validación del controlador
        registerRequest.setFirstName("Test");
        registerRequest.setLastName("User");

        // 4. Ejecutar el metodo a probar
        assertDoesNotThrow(() -> keycloakService.createUser(testRealm, registerRequest));

        // 5. Verificar las interacciones con los mocks
        // Verificar que keycloak.realm fue llamado con el realm correcto.
        verify(keycloak, times(1)).realm(testRealm); // CORREGIDO: Se llama solo 1 vez
        // Verificar que usersResource.create fue llamado una vez con cualquier UserRepresentation.
        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        // Verificar que response.getStatus() fue llamado una vez.
        verify(response, times(1)).getStatus();
        // Verificar que response.getLocation() fue llamado una vez.
        verify(response, times(1)).getLocation();
        // Verificar que realmResource.users().get(userId) fue llamado una vez con el ID correcto.
        verify(realmResource.users(), times(1)).get(testUserId);
        // Verificar que userResource.resetPassword fue llamado una vez con cualquier CredentialRepresentation.
        verify(userResource, times(1)).resetPassword(any(CredentialRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si la creación de usuario falla con un estado no 201")
    void createUser_FailureStatus() {
        // Configurar el comportamiento del mock para la creación de usuario
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        // Simular un estado de respuesta que no sea 201 (ej. 409 Conflict si el usuario ya existe)
        when(response.getStatus()).thenReturn(409);
        // Simular el cuerpo de la respuesta de error
        when(response.readEntity(String.class)).thenReturn("User with username already exists");

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(testUsername);
        registerRequest.setEmail(testEmail);
        registerRequest.setPassword(testPassword);
        registerRequest.setConfirmPassword(testPassword);
        registerRequest.setFirstName("Test");
        registerRequest.setLastName("User");

        // Ejecutar el metodo y verificar que lanza la excepción esperada
        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                keycloakService.createUser(testRealm, registerRequest));

        // Verificar el mensaje de la excepción
        assertTrue(exception.getMessage().contains("Error al crear usuario en Keycloak. Estado HTTP: 409."));
        assertTrue(exception.getMessage().contains("User with username already exists"));

        // Verificar interacciones (que no se intentó establecer la contraseña)
        verify(keycloak, times(1)).realm(testRealm); // Se llama solo 1 vez al inicio del método createUser
        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(3)).getStatus(); // CORREGIDO: Se llama 3 veces en el bloque 'else'
        verify(response, times(1)).readEntity(String.class);
        verify(realmResource.users(), never()).get(anyString()); // Verificar que no se llamó a get(userId)
        verify(userResource, never()).resetPassword(any(CredentialRepresentation.class)); // Verificar que no se llamó a resetPassword
    }

    @Test
    @DisplayName("Debería lanzar excepción si falla el establecimiento de contraseña")
    void createUser_PasswordResetFailure() {
        // Configurar el comportamiento del mock para la creación de usuario (éxito)
        when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);
        when(response.getStatus()).thenReturn(201);
        when(response.getLocation()).thenReturn(URI.create("http://localhost/users/" + testUserId));

        // Configurar el comportamiento del mock para el establecimiento de contraseña (falla)
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

        // Ejecutar el metodo y verificar que lanza la excepción esperada
        KeycloakUserCreationException exception = assertThrows(KeycloakUserCreationException.class, () ->
                keycloakService.createUser(testRealm, registerRequest));

        // Verificar el mensaje de la excepción
        assertTrue(exception.getMessage().contains("Error al establecer la contraseña para el usuario"));
        assertTrue(exception.getMessage().contains("Keycloak API error during password reset"));

        // Verificar interacciones
        verify(keycloak, times(1)).realm(testRealm); // CORREGIDO: Se llama solo 1 vez
        verify(usersResource, times(1)).create(any(UserRepresentation.class));
        verify(response, times(1)).getStatus();
        verify(response, times(1)).getLocation();
        verify(realmResource.users(), times(1)).get(testUserId);
        verify(userResource, times(1)).resetPassword(any(CredentialRepresentation.class));
    }


    @Test
    @DisplayName("Debería retornar true si el email ya existe en Keycloak")
    void userExistsByEmail_EmailExists() {
        // Configurar el comportamiento del mock: usersResource.searchByEmail debe devolver una lista no vacía
        when(usersResource.searchByEmail(testEmail, true))
                .thenReturn(Collections.singletonList(new UserRepresentation())); // Simula que se encontró un usuario

        // Ejecutar el metodo y verificar el resultado
        assertTrue(keycloakService.userExistsByEmail(testRealm, testEmail));

        // Verificar interacciones
        verify(keycloak, times(1)).realm(testRealm);
        verify(realmResource, times(1)).users();
        verify(usersResource, times(1)).searchByEmail(testEmail, true);
    }

    @Test
    @DisplayName("Debería retornar false si el email no existe en Keycloak")
    void userExistsByEmail_EmailDoesNotExist() {
        // Configurar el comportamiento del mock: usersResource.searchByEmail debe devolver una lista vacía
        when(usersResource.searchByEmail(testEmail, true))
                .thenReturn(Collections.emptyList()); // Simula que no se encontró ningún usuario

        // Ejecutar el metodo y verificar el resultado
        assertFalse(keycloakService.userExistsByEmail(testRealm, testEmail));

        // Verificar interacciones
        verify(keycloak, times(1)).realm(testRealm);
        verify(realmResource, times(1)).users();
        verify(usersResource, times(1)).searchByEmail(testEmail, true);
    }
}
