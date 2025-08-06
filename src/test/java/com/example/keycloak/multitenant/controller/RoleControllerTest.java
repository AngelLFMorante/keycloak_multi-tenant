package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.KeycloakService;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.idm.RoleRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

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
import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertNotNull;
import static org.springframework.test.util.AssertionErrors.assertTrue;

/**
 * Clase de test unitario para {@link RoleController}.
 * Utiliza {@link WebMvcTest} para probar el controlador de forma aislada,
 * simulando las dependencias con {@link MockitoBean}.
 */
@ExtendWith(MockitoExtension.class)
class RoleControllerTest {

    @Mock
    private KeycloakService keycloakService;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private RoleController roleController;

    private final String TEST_REALM_PATH = "mytenant";
    private final String TEST_KEYCLOAK_REALM = "mytenant-realm";
    private final String TEST_ROLE_NAME = "TEST_ROLE";
    private final String TEST_ROLE_DESCRIPTION = "Description for test role";

    @Test
    @DisplayName("GET /roles - Debería obtener roles exitosamente")
    void getRoles_Success() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(TEST_REALM_PATH, TEST_KEYCLOAK_REALM);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);

        RoleRepresentation role1 = new RoleRepresentation();
        role1.setName("admin");
        RoleRepresentation role2 = new RoleRepresentation();
        role2.setName("user");
        List<RoleRepresentation> mockRoles = Arrays.asList(role1, role2);
        when(keycloakService.getRoles(TEST_KEYCLOAK_REALM)).thenReturn(mockRoles);

        ResponseEntity<List<RoleRepresentation>> responseEntity = roleController.getRoles(TEST_REALM_PATH);

        assertNotNull(String.valueOf(responseEntity), "La entidad de respuesta no debería ser nula");
        assertEquals("El estado HTTP debería ser OK", HttpStatus.OK, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody().toString(), "El cuerpo de la respuesta no debería ser nulo");
        assertEquals("El tamaño de la lista de roles debería ser 2", 2, responseEntity.getBody().size());
        assertEquals("admin", responseEntity.getBody().get(0).getName(), "admin");
        assertEquals("user", responseEntity.getBody().get(1).getName(), "user");


        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, times(1)).getRoles(TEST_KEYCLOAK_REALM);
    }

    @Test
    @DisplayName("GET /roles - Debería retornar 404 si el tenant no es reconocido")
    void getRoles_NotFoundTenant() {
        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                roleController.getRoles(TEST_REALM_PATH)
        );

        assertEquals("El estado HTTP debería ser NOT_FOUND", HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue("El mensaje de la excepción debería indicar tenant no reconocido",
                exception.getReason().contains("Realm " + TEST_REALM_PATH + " no reconocido."));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, never()).getRoles(anyString());
    }

    @Test
    @DisplayName("GET /roles - Debería retornar 500 si el servicio Keycloak falla")
    void getRoles_ServiceFailure() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(TEST_REALM_PATH, TEST_KEYCLOAK_REALM);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        when(keycloakService.getRoles(TEST_KEYCLOAK_REALM)).thenThrow(new RuntimeException("Keycloak API error"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                roleController.getRoles(TEST_REALM_PATH)
        );

        assertEquals("El estado HTTP debería ser INTERNAL_SERVER_ERROR", HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertTrue("El mensaje de la excepción debería contener el error del servicio",
                exception.getReason().contains("error al obtener roles: Keycloak API error"));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, times(1)).getRoles(TEST_KEYCLOAK_REALM);
    }

    @Test
    @DisplayName("POST /roles - Debería crear un rol exitosamente")
    void createRole_Success() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(TEST_REALM_PATH, TEST_KEYCLOAK_REALM);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        doNothing().when(keycloakService).createRole(eq(TEST_KEYCLOAK_REALM), any(CreateRoleRequest.class));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(TEST_ROLE_NAME);
        request.setDescription(TEST_ROLE_DESCRIPTION);

        ResponseEntity<Map<String, Object>> responseEntity = roleController.createRole(TEST_REALM_PATH, request);

        assertNotNull(String.valueOf(responseEntity), "La entidad de respuesta no debería ser nula");
        assertEquals("El estado HTTP debería ser CREATED", HttpStatus.CREATED, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody().toString(), "El cuerpo de la respuesta no debería ser nulo");
        assertEquals("Rol creado exitosamente.", responseEntity.getBody().get("message"), "Rol creado exitosamente.");
        assertEquals(TEST_ROLE_NAME, responseEntity.getBody().get("roleName"), "TEST_ROLE");

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, times(1)).createRole(eq(TEST_KEYCLOAK_REALM), any(CreateRoleRequest.class));
    }

    @Test
    @DisplayName("POST /roles - Debería retornar 404 si el tenant no es reconocido")
    void createRole_NotFoundTenant() {
        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(TEST_ROLE_NAME);
        request.setDescription(TEST_ROLE_DESCRIPTION);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                roleController.createRole(TEST_REALM_PATH, request)
        );

        assertEquals("El estado HTTP debería ser NOT_FOUND", HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue("El mensaje de la excepción debería indicar tenant no reconocido",
                exception.getReason().contains("Realm " + TEST_REALM_PATH + "no reconocido."));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, never()).createRole(anyString(), any(CreateRoleRequest.class));
    }

    @Test
    @DisplayName("POST /roles - Debería retornar 500 si el servicio Keycloak falla")
    void createRole_ServiceFailure() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(TEST_REALM_PATH, TEST_KEYCLOAK_REALM);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        doThrow(new RuntimeException("Keycloak API error during role creation")).when(keycloakService).createRole(eq(TEST_KEYCLOAK_REALM), any(CreateRoleRequest.class));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(TEST_ROLE_NAME);
        request.setDescription(TEST_ROLE_DESCRIPTION);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                roleController.createRole(TEST_REALM_PATH, request)
        );

        assertEquals("El estado HTTP debería ser INTERNAL_SERVER_ERROR", HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertTrue("El mensaje de la excepción debería contener el error del servicio",
                exception.getReason().contains("Error al crear el rol: Keycloak API error during role creation"));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, times(1)).createRole(eq(TEST_KEYCLOAK_REALM), any(CreateRoleRequest.class));
    }

    @Test
    @DisplayName("DELETE /roles/{roleName} - Debería eliminar un rol exitosamente")
    void deleteRole_Success() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(TEST_REALM_PATH, TEST_KEYCLOAK_REALM);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        doNothing().when(keycloakService).deleteRole(TEST_KEYCLOAK_REALM, TEST_ROLE_NAME);

        ResponseEntity<Map<String, Object>> responseEntity = roleController.deleteRole(TEST_REALM_PATH, TEST_ROLE_NAME);

        assertNotNull(String.valueOf(responseEntity), "La entidad de respuesta no debería ser nula");
        assertEquals("El estado HTTP debería ser OK", HttpStatus.OK, responseEntity.getStatusCode());
        assertNotNull(responseEntity.getBody().toString(), "El cuerpo de la respuesta no debería ser nulo");
        assertEquals("Rol '" + TEST_ROLE_NAME + "' eliminado exitosamente.",
                responseEntity.getBody().get("message"), "Rol 'TEST_ROLE' eliminado exitosamente.");

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, times(1)).deleteRole(TEST_KEYCLOAK_REALM, TEST_ROLE_NAME);
    }

    @Test
    @DisplayName("DELETE /roles/{roleName} - Debería retornar 404 si el tenant no es reconocido")
    void deleteRole_NotFoundTenant() {
        when(keycloakProperties.getRealmMapping()).thenReturn(Collections.emptyMap());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                roleController.deleteRole(TEST_REALM_PATH, TEST_ROLE_NAME)
        );

        assertEquals("El estado HTTP debería ser NOT_FOUND", HttpStatus.NOT_FOUND, exception.getStatusCode());
        assertTrue("El mensaje de la excepción debería indicar tenant no reconocido",
                exception.getReason().contains("Realm " + TEST_REALM_PATH + " no reconocido."));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, never()).deleteRole(anyString(), anyString());
    }


    @Test
    @DisplayName("DELETE /roles/{roleName} - Debería retornar 500 si el servicio Keycloak falla")
    void deleteRole_ServiceFailure() {
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put(TEST_REALM_PATH, TEST_KEYCLOAK_REALM);
        when(keycloakProperties.getRealmMapping()).thenReturn(realmMapping);
        doThrow(new RuntimeException("Keycloak API error during role deletion")).when(keycloakService).deleteRole(TEST_KEYCLOAK_REALM, TEST_ROLE_NAME);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                roleController.deleteRole(TEST_REALM_PATH, TEST_ROLE_NAME)
        );

        assertEquals("El estado HTTP debería ser INTERNAL_SERVER_ERROR", HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatusCode());
        assertTrue("El mensaje de la excepción debería contener el error del servicio",
                exception.getReason().contains("Error al eliminar el rol: Keycloak API error during role deletion"));

        verify(keycloakProperties, times(1)).getRealmMapping();
        verify(keycloakService, times(1)).deleteRole(TEST_KEYCLOAK_REALM, TEST_ROLE_NAME);
    }
}