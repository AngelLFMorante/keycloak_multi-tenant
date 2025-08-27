package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.RoleService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.idm.RoleRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
/*
@ExtendWith(MockitoExtension.class)
class RoleControllerTest {

    @Mock
    private RoleService roleService;

    @InjectMocks
    private RoleController roleController;

    private String realm;
    private String roleName;

    @BeforeEach
    void setUp() {
        realm = "testRealm";
        roleName = "ADMIN_ROLE";
    }

    @Test
    @DisplayName("Debería obtener la lista de roles")
    void getRoles_ShouldReturnRoles() {
        List<RoleRepresentation> mockRoles = List.of(new RoleRepresentation());
        when(roleService.getRolesByRealm(realm)).thenReturn(mockRoles);

        ResponseEntity<List<RoleRepresentation>> response = roleController.getRoles(realm);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(mockRoles, response.getBody());
        verify(roleService).getRolesByRealm(realm);
    }

    @Test
    @DisplayName("Debería crear un rol exitosamente")
    void createRole_ShouldReturnCreatedResponse() {
        CreateRoleRequest request = new CreateRoleRequest();
        request.name(roleName);

        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("message", "Rol creado exitosamente");
        mockResponse.put("roleName", roleName);
        mockResponse.put("realm", realm);

        when(roleService.createRoleInRealm(realm, request)).thenReturn(mockResponse);

        ResponseEntity<Map<String, Object>> response = roleController.createRole(realm, request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(mockResponse, response.getBody());
        verify(roleService).createRoleInRealm(realm, request);
    }

    @Test
    @DisplayName("Debería eliminar un rol exitosamente")
    void deleteRole_ShouldReturnOkResponse() {
        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("message", "Rol eliminado exitosamente");
        mockResponse.put("roleName", roleName);
        mockResponse.put("realm", realm);

        when(roleService.deleteRoleFromRealm(realm, roleName)).thenReturn(mockResponse);

        ResponseEntity<Map<String, Object>> response = roleController.deleteRole(realm, roleName);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(mockResponse, response.getBody());
        verify(roleService).deleteRoleFromRealm(realm, roleName);
    }

    @Test
    @DisplayName("Debería obtener atributos de un rol")
    void getRoleAttributes_ShouldReturnAttributes() {
        Map<String, List<String>> attributes = Map.of("key1", List.of("value1"));
        when(roleService.getRoleAttributes(realm, roleName)).thenReturn(attributes);

        ResponseEntity<Map<String, List<String>>> response = roleController.getRoleAttributes(realm, roleName);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(attributes, response.getBody());
        verify(roleService).getRoleAttributes(realm, roleName);
    }

    @Test
    @DisplayName("Debería añadir o actualizar atributos de un rol")
    void addOrUpdateRoleAttributes_ShouldReturnNoContent() {
        Map<String, List<String>> attributes = Map.of("key1", List.of("value1"));

        ResponseEntity<Void> response = roleController.addOrUpdateRoleAttributes(realm, roleName, attributes);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(roleService).addOrUpdateRoleAttributes(realm, roleName, attributes);
    }

    @Test
    @DisplayName("Debería eliminar atributo de un rol")
    void removeRoleAttribute_ShouldReturnNoContent() {
        String attribute = "attributeName";
        ResponseEntity<Void> response = roleController.removeRoleAttribute(realm, roleName, attribute);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(roleService).removeRoleAttribute(realm, roleName, attribute);
    }
}*/
