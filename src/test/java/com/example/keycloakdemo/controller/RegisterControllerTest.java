package com.example.keycloakdemo.controller;

import com.example.keycloakdemo.exception.KeycloakUserCreationException;
import com.example.keycloakdemo.model.RegisterRequest;
import com.example.keycloakdemo.service.KeycloakService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Clase de test de integración para {@link RegisterController}.
 * Utiliza {@link WebMvcTest} para probar la capa web (controlador y configuración de seguridad)
 * sin levantar todo el contexto de Spring Boot. {@link MockMvc} se usa para simular solicitudes HTTP.
 * Las dependencias del controlador (ej. {@link KeycloakService}) se mockean.
 *
 * Se excluyen las auto-configuraciones de OAuth2 Client ya que la aplicación no utiliza
 * el flujo de autenticación estándar de Spring Security con OAuth2/OIDC.
 */
@WebMvcTest(
        controllers = RegisterController.class,
        excludeAutoConfiguration = { // Excluir auto-configuraciones de OAuth2 Client
                OAuth2ClientAutoConfiguration.class,
                OAuth2ClientWebSecurityAutoConfiguration.class
        }
)
// En RegisterControllerIntegrationTest.java
@Import({com.example.keycloakdemo.config.SecurityConfig.class, com.example.keycloakdemo.config.GlobalExceptionHandler.class, org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration.class})
class RegisterControllerTest {

    @Autowired
    private MockMvc mockMvc; // Inyecta MockMvc para simular solicitudes HTTP

    @Autowired
    private ObjectMapper objectMapper; // Para convertir objetos Java a JSON y viceversa

    @MockitoBean // Crea un mock de KeycloakService y lo inyecta en el contexto de Spring
    private KeycloakService keycloakService;

    private String testTenantIdentifier = "plexus";
    private String registerUrl = "/" + testTenantIdentifier + "/register";

    @Test
    @DisplayName("GET /register debería retornar 200 OK con información del endpoint")
    void getRegisterForm_ReturnsOk() throws Exception {
        mockMvc.perform(get(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()) // Espera un estado HTTP 200 OK
                .andExpect(jsonPath("$.realm").value(testTenantIdentifier))
                .andExpect(jsonPath("$.registerRequest").exists());
    }

    @Test
    @DisplayName("POST /register debería registrar un usuario exitosamente y retornar 201 Created")
    void registerUser_Success() throws Exception {
        // Configurar mocks para el servicio Keycloak
        when(keycloakService.userExistsByEmail(anyString(), anyString())).thenReturn(false); // Email no existe
        doNothing().when(keycloakService).createUser(anyString(), any(RegisterRequest.class)); // Creación exitosa

        // Crear una solicitud de registro válida
        RegisterRequest validRequest = new RegisterRequest();
        validRequest.setUsername("newuser");
        validRequest.setPassword("SecurePass123!");
        validRequest.setConfirmPassword("SecurePass123!");
        validRequest.setEmail("newuser@example.com");
        validRequest.setFirstName("New");
        validRequest.setLastName("User");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest))) // Convierte el objeto a JSON
                .andExpect(status().isCreated()) // Espera un estado HTTP 201 Created
                .andExpect(jsonPath("$.message").value("User registered. Waiting for admin approval."))
                .andExpect(jsonPath("$.tenantId").value(testTenantIdentifier));

        // Verificar que los métodos del servicio fueron llamados
        verify(keycloakService, times(1)).userExistsByEmail(anyString(), eq(validRequest.getEmail()));
        verify(keycloakService, times(1)).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /register debería retornar 400 Bad Request si las contraseñas no coinciden")
    void registerUser_PasswordsMismatch_ReturnsBadRequest() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("user");
        request.setPassword("SecurePass1!");
        request.setConfirmPassword("SecurePass2!"); // Contraseñas no coinciden
        request.setEmail("user@example.com");
        request.setFirstName("Test");
        request.setLastName("User");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest()) // Espera un estado HTTP 400 Bad Request
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Password no coinciden"));

        // Verificar que no hubo interacciones con keycloakService
        verify(keycloakService, never()).userExistsByEmail(anyString(), anyString());
        verify(keycloakService, never()).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /register debería retornar 400 Bad Request si el email ya existe")
    void registerUser_EmailAlreadyExists_ReturnsBadRequest() throws Exception {
        // Configurar mock: userExistsByEmail debe retornar true
        when(keycloakService.userExistsByEmail(anyString(), anyString())).thenReturn(true);

        RegisterRequest request = new RegisterRequest();
        request.setUsername("existinguser");
        request.setPassword("SecurePass123!");
        request.setConfirmPassword("SecurePass123!");
        request.setEmail("existing@example.com"); // Email que ya existe
        request.setFirstName("Existing");
        request.setLastName("User");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest()) // Espera un estado HTTP 400 Bad Request
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("El email 'existing@example.com' ya está registrado en Keycloak."));

        // Verificar interacciones
        verify(keycloakService, times(1)).userExistsByEmail(anyString(), eq(request.getEmail()));
        verify(keycloakService, never()).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /register debería retornar 400 Bad Request si faltan campos requeridos (Bean Validation)")
    void registerUser_MissingRequiredFields_ReturnsBadRequest() throws Exception {
        RegisterRequest invalidRequest = new RegisterRequest();
        invalidRequest.setUsername(""); // Campo vacío, @NotBlank
        invalidRequest.setPassword("pass"); // Contraseña muy corta, @Size
        invalidRequest.setConfirmPassword("pass");
        invalidRequest.setEmail("invalid-email");// Formato de email inválido, @Email
        invalidRequest.setFirstName("");
        invalidRequest.setLastName("");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest()) // Espera un estado HTTP 400 Bad Request
                .andExpect(jsonPath("$.error").value("Validation Failed"))
                .andExpect(jsonPath("$.message").value("Uno o mas campos tienen errores de validacion"))
                .andExpect(jsonPath("$.details.username").value("El nombre de usuario no puede estar vacio"))
                .andExpect(jsonPath("$.details.password").value("La contraseña debe tener al menos 8 caracteres"))
                .andExpect(jsonPath("$.details.email").value("El email debe tener un formato valido"))
                .andExpect(jsonPath("$.details.firstName").value("El nombre no puede estar vacio"))
                .andExpect(jsonPath("$.details.lastName").value("El apellido no puede estar vacio"));

        // Verificar que no hubo interacciones con keycloakService
        verify(keycloakService, never()).userExistsByEmail(anyString(), anyString());
        verify(keycloakService, never()).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /register debería retornar 409 Conflict si KeycloakUserCreationException indica conflicto")
    void registerUser_KeycloakServiceThrowsConflictException_ReturnsConflict() throws Exception {
        // Configurar mocks:
        when(keycloakService.userExistsByEmail(anyString(), anyString())).thenReturn(false);
        // Simular que createUser lanza una KeycloakUserCreationException con mensaje de conflicto
        doThrow(new KeycloakUserCreationException("Error al crear usuario en Keycloak. Estado HTTP: 409. Detalles: User exists with same username."))
                .when(keycloakService).createUser(anyString(), any(RegisterRequest.class));

        RegisterRequest request = new RegisterRequest();
        request.setUsername("conflictuser");
        request.setPassword("SecurePass123!");
        request.setConfirmPassword("SecurePass123!");
        request.setEmail("conflict@example.com");
        request.setFirstName("Conflict");
        request.setLastName("User");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict()) // Espera un estado HTTP 409 Conflict
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.message").value("Error al crear usuario en Keycloak. Estado HTTP: 409. Detalles: User exists with same username."));

        // Verificar interacciones
        verify(keycloakService, times(1)).userExistsByEmail(anyString(), eq(request.getEmail()));
        verify(keycloakService, times(1)).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /register debería retornar 500 Internal Server Error si KeycloakUserCreationException es genérica") // CAMBIO: Nombre del DisplayName
    void registerUser_KeycloakServiceThrowsGenericException_ReturnsInternalServerError() throws Exception { // CAMBIO: Nombre del método
        // Configurar mocks:
        when(keycloakService.userExistsByEmail(anyString(), anyString())).thenReturn(false);
        // Simular que createUser lanza una KeycloakUserCreationException genérica
        doThrow(new KeycloakUserCreationException("Error interno al crear usuario: Problema de conexión con Keycloak."))
                .when(keycloakService).createUser(anyString(), any(RegisterRequest.class));

        RegisterRequest request = new RegisterRequest();
        request.setUsername("internalerror");
        request.setPassword("SecurePass123!");
        request.setConfirmPassword("SecurePass123!");
        request.setEmail("internal@example.com");
        request.setFirstName("Internal");
        request.setLastName("Error");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError()) // CAMBIO: Espera 500
                .andExpect(jsonPath("$.error").value("Internal Server Error")) // CAMBIO: Espera "Internal Server Error"
                .andExpect(jsonPath("$.message").value("Error interno al crear usuario: Problema de conexión con Keycloak."));

        // Verificar interacciones
        verify(keycloakService, times(1)).userExistsByEmail(anyString(), eq(request.getEmail()));
        verify(keycloakService, times(1)).createUser(anyString(), any(RegisterRequest.class));
    }

    @Test
    @DisplayName("POST /register debería retornar 500 Internal Server Error para excepciones inesperadas")
    void registerUser_UnexpectedException_ReturnsInternalServerError() throws Exception {
        // Configurar mocks:
        when(keycloakService.userExistsByEmail(anyString(), anyString())).thenReturn(false);
        // Simular que createUser lanza una RuntimeException inesperada
        doThrow(new RuntimeException("Error inesperado en el servicio de Keycloak."))
                .when(keycloakService).createUser(anyString(), any(RegisterRequest.class));

        RegisterRequest request = new RegisterRequest();
        request.setUsername("unexpected");
        request.setPassword("SecurePass123!");
        request.setConfirmPassword("SecurePass123!");
        request.setEmail("unexpected@example.com");
        request.setFirstName("Unexpected");
        request.setLastName("Error");

        mockMvc.perform(post(registerUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError()) // Espera un estado HTTP 500
                .andExpect(jsonPath("$.error").value("Internal Server Error"))
                .andExpect(jsonPath("$.message").value("Ocurrió un error inesperado. Por favor, intente de nuevo mas tarde."));

        // Verificar interacciones
        verify(keycloakService, times(1)).userExistsByEmail(anyString(), eq(request.getEmail()));
        verify(keycloakService, times(1)).createUser(anyString(), any(RegisterRequest.class));
    }
}
