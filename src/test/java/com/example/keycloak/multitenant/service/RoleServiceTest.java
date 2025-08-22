package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakRoleService;
import com.example.keycloak.multitenant.service.keycloak.KeycloakUtilsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RoleRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RoleServiceTest {

    @Mock
    private KeycloakRoleService keycloakRoleService;

    @Mock
    private KeycloakUtilsService utilsService;

    @InjectMocks
    private RoleService roleService;

    private String realm;
    private String keycloakRealm;
    private String roleName;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        realm = "testRealm";
        keycloakRealm = "kcTestRealm";
        roleName = "ADMIN_ROLE";

        when(utilsService.resolveRealm(realm)).thenReturn(keycloakRealm);
    }

    @Test
    @DisplayName("Debería obtener roles de un realm")
    void getRolesByRealm_ShouldReturnRoles() {
        List<RoleRepresentation> mockRoles = List.of(new RoleRepresentation());
        when(keycloakRoleService.getRoles(keycloakRealm)).thenReturn(mockRoles);

        List<RoleRepresentation> result = roleService.getRolesByRealm(realm);

        assertEquals(mockRoles, result);
        verify(keycloakRoleService).getRoles(keycloakRealm);
    }

    @Test
    @DisplayName("Debería crear un rol en un realm")
    void createRoleInRealm_ShouldReturnResponseMap() {
        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(roleName);

        Map<String, Object> response = roleService.createRoleInRealm(realm, request);

        assertEquals("Rol creado exitosamente", response.get("message"));
        assertEquals(roleName, response.get("roleName"));
        assertEquals(realm, response.get("realm"));
        verify(keycloakRoleService).createRole(keycloakRealm, request);
    }

    @Test
    @DisplayName("Debería eliminar un rol de un realm")
    void deleteRoleFromRealm_ShouldReturnResponseMap() {
        Map<String, Object> response = roleService.deleteRoleFromRealm(realm, roleName);

        assertEquals("Rol eliminado exitosamente", response.get("message"));
        assertEquals(roleName, response.get("roleName"));
        assertEquals(realm, response.get("realm"));
        verify(keycloakRoleService).deleteRole(keycloakRealm, roleName);
    }

    @Test
    @DisplayName("Debería obtener atributos de un rol")
    void getRoleAttributes_ShouldReturnAttributes() {
        Map<String, List<String>> mockAttributes = new HashMap<>();
        mockAttributes.put("attr1", List.of("val1"));
        when(keycloakRoleService.getRoleAttributes(keycloakRealm, roleName)).thenReturn(mockAttributes);

        Map<String, List<String>> result = roleService.getRoleAttributes(realm, roleName);

        assertEquals(mockAttributes, result);
        verify(keycloakRoleService).getRoleAttributes(keycloakRealm, roleName);
    }

    @Test
    @DisplayName("Debería añadir o actualizar atributos de un rol")
    void addOrUpdateRoleAttributes_ShouldCallKeycloakRoleService() {
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("attr1", List.of("val1"));

        roleService.addOrUpdateRoleAttributes(realm, roleName, attributes);

        verify(keycloakRoleService).addOrUpdateRoleAttributes(keycloakRealm, roleName, attributes);
    }
}
