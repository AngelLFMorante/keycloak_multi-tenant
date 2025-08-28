package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.service.keycloak.KeycloakRoleService;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleServiceTest {

    @Mock
    private KeycloakRoleService keycloakRoleService;

    @InjectMocks
    private RoleService roleService;

    private String realm;
    private String roleName;
    private CreateRoleRequest createRoleRequest;
    private Map<String, List<String>> roleAttributes;

    @BeforeEach
    void setUp() {
        realm = "test-realm";
        roleName = "test-role";
        createRoleRequest = new CreateRoleRequest("new-role", "Description of new role");
        roleAttributes = new HashMap<>();
        roleAttributes.put("attribute1", List.of("value1"));
        roleAttributes.put("attribute2", List.of("value2"));
    }

    @Test
    @DisplayName("Debería obtener todos los roles de un realm")
    void getRolesByRealm_shouldReturnRoles() {
        List<RoleRepresentation> mockRoles = List.of(
                new RoleRepresentation("role-one", null, false),
                new RoleRepresentation("role-two", null, false)
        );
        when(keycloakRoleService.getRoles(realm)).thenReturn(mockRoles);

        List<RoleRepresentation> roles = roleService.getRolesByRealm(realm);

        assertNotNull(roles);
        assertEquals(2, roles.size());
        verify(keycloakRoleService, times(1)).getRoles(realm);
    }

    @Test
    @DisplayName("Debería crear un nuevo rol y devolver un mensaje de éxito")
    void createRoleInRealm_shouldReturnSuccessMessage_whenRoleIsCreated() {
        doNothing().when(keycloakRoleService).createRole(realm, createRoleRequest);

        Map<String, Object> response = roleService.createRoleInRealm(realm, createRoleRequest);

        assertNotNull(response);
        assertEquals("Rol creado exitosamente", response.get("message"));
        assertEquals(createRoleRequest.name(), response.get("roleName"));
        verify(keycloakRoleService, times(1)).createRole(realm, createRoleRequest);
    }

    @Test
    @DisplayName("Debería eliminar un rol y devolver un mensaje de éxito")
    void deleteRoleFromRealm_shouldReturnSuccessMessage_whenRoleIsDeleted() {
        doNothing().when(keycloakRoleService).deleteRole(realm, roleName);

        Map<String, Object> response = roleService.deleteRoleFromRealm(realm, roleName);

        assertNotNull(response);
        assertEquals("Rol eliminado exitosamente", response.get("message"));
        assertEquals(roleName, response.get("roleName"));
        verify(keycloakRoleService, times(1)).deleteRole(realm, roleName);
    }

    @Test
    @DisplayName("Debería obtener los atributos de un rol")
    void getRoleAttributes_shouldReturnAttributes_whenRoleHasAttributes() {
        when(keycloakRoleService.getRoleAttributes(realm, roleName)).thenReturn(roleAttributes);

        Map<String, List<String>> result = roleService.getRoleAttributes(realm, roleName);

        assertNotNull(result);
        assertEquals(roleAttributes, result);
        verify(keycloakRoleService, times(1)).getRoleAttributes(realm, roleName);
    }

    @Test
    @DisplayName("Debería añadir o actualizar atributos de un rol")
    void addOrUpdateRoleAttributes_shouldCallKeycloakRoleService() {
        doNothing().when(keycloakRoleService).addOrUpdateRoleAttributes(realm, roleName, roleAttributes);

        roleService.addOrUpdateRoleAttributes(realm, roleName, roleAttributes);

        verify(keycloakRoleService, times(1)).addOrUpdateRoleAttributes(realm, roleName, roleAttributes);
    }

    @Test
    @DisplayName("Debería eliminar un atributo de un rol")
    void removeRoleAttribute_shouldCallKeycloakRoleService() {
        String attributeName = "attribute1";
        doNothing().when(keycloakRoleService).removeRoleAttribute(realm, roleName, attributeName);

        roleService.removeRoleAttribute(realm, roleName, attributeName);

        verify(keycloakRoleService, times(1)).removeRoleAttribute(realm, roleName, attributeName);
    }
}
