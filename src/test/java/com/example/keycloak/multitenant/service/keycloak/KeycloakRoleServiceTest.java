package com.example.keycloak.multitenant.service.keycloak;

import com.example.keycloak.multitenant.exception.KeycloakRoleCreationException;
import com.example.keycloak.multitenant.model.CreateRoleRequest;
import com.example.keycloak.multitenant.model.UserRequest;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;
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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class KeycloakRoleServiceTest {

    @Mock
    private KeycloakUtilsService utilsService;

    @Mock
    private RealmResource realmResource;

    @Mock
    private RolesResource rolesResource;

    @Mock
    private RoleResource roleResource;

    @InjectMocks
    private KeycloakRoleService roleService;

    private final String realm = "plexus";
    private final String testRole = "ADMIN_ROLE";

    @Test
    @DisplayName("Debería obtener roles correctamente")
    void getRoles_Success() {
        RoleRepresentation role1 = new RoleRepresentation();
        role1.setName("role1");
        RoleRepresentation role2 = new RoleRepresentation();
        role2.setName("role2");

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Arrays.asList(role1, role2));

        List<RoleRepresentation> result = roleService.getRoles(realm);

        assertNotNull(result);
        assertEquals(2, result.size());
        verify(rolesResource, times(1)).list();
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si falla obtener roles")
    void getRoles_Failure() {
        when(rolesResource.list()).thenThrow(new RuntimeException("Error de Keycloak"));

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                roleService.getRoles(realm)
        );

        assertTrue(exception.getMessage().contains("Error inesperado al obtener roles"));
    }

    @Test
    @DisplayName("Debería crear rol exitosamente cuando no existe")
    void createRole_Success() {
        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRole);
        request.setDescription("Rol de administrador");

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.emptyList());
        doNothing().when(rolesResource).create(any(RoleRepresentation.class));

        assertDoesNotThrow(() -> roleService.createRole(realm, request));

        verify(rolesResource, times(1)).create(any(RoleRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si el rol ya existe")
    void createRole_AlreadyExists() {
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(testRole);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.singletonList(existingRole));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRole);

        KeycloakRoleCreationException exception = assertThrows(KeycloakRoleCreationException.class, () ->
                roleService.createRole(realm, request)
        );

        assertTrue(exception.getMessage().contains("ya existe"));
    }

    @Test
    @DisplayName("Debería lanzar KeycloakRoleCreationException si falla con WebApplicationException")
    void createRole_WebApplicationError() {
        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.emptyList());
        WebApplicationException webException = new WebApplicationException(Response.status(400).entity("Invalid role").build());

        doThrow(webException).when(rolesResource).create(any(RoleRepresentation.class));

        CreateRoleRequest request = new CreateRoleRequest();
        request.setName(testRole);

        KeycloakRoleCreationException exception = assertThrows(KeycloakRoleCreationException.class, () ->
                roleService.createRole(realm, request)
        );

        assertTrue(exception.getMessage().contains("Estado HTTP: 400"));
    }

    @Test
    @DisplayName("Debería eliminar rol exitosamente cuando existe")
    void deleteRole_Success() {
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(testRole);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.singletonList(existingRole));
        doNothing().when(rolesResource).deleteRole(testRole);

        assertDoesNotThrow(() -> roleService.deleteRole(realm, testRole));

        verify(rolesResource, times(1)).deleteRole(testRole);
    }

    @Test
    @DisplayName("Debería lanzar NotFoundException si el rol no existe")
    void deleteRole_NotFound() {
        when(rolesResource.list()).thenReturn(Collections.emptyList());

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        NotFoundException exception = assertThrows(NotFoundException.class, () ->
                roleService.deleteRole(realm, testRole)
        );

        assertTrue(exception.getMessage().contains("no encontrado"));
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si falla la eliminación")
    void deleteRole_Failure() {
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(testRole);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.list()).thenReturn(Collections.singletonList(existingRole));
        doThrow(new RuntimeException("Error interno")).when(rolesResource).deleteRole(testRole);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                roleService.deleteRole(realm, testRole)
        );

        assertTrue(exception.getMessage().contains("Error inesperado"));
    }

    @Test
    @DisplayName("Debería validar que el rol existe")
    void checkRole_ShouldPass_WhenRoleExists() {
        RoleRepresentation roleRepresentation = new RoleRepresentation();
        roleRepresentation.setName(testRole);

        List<RoleRepresentation> roles = new ArrayList<>();
        roles.add(roleRepresentation);

        UserRequest userRequest = new UserRequest();
        userRequest.setRole(testRole);
        userRequest.setUsername("username");
        userRequest.setLastName("lastname");
        userRequest.setFirstName("firstname");
        userRequest.setEmail("email@gmail.com");

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(roleService.getRoles(realm)).thenReturn(roles);

        assertDoesNotThrow(() -> roleService.checkRole(realm, userRequest));
    }

    @Test
    @DisplayName("Debería lanzar excepción si el rol no existe")
    void checkRole_ShouldThrow_WhenRoleDoesNotExist() {
        List<RoleRepresentation> roles = new ArrayList<>();
        RoleRepresentation anotherRole = new RoleRepresentation();
        anotherRole.setName("USER");
        roles.add(anotherRole);

        UserRequest userRequest = new UserRequest();
        userRequest.setRole(testRole);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(roleService.getRoles(realm)).thenReturn(roles);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> roleService.checkRole(realm, userRequest));

        assertEquals("El role 'ADMIN_ROLE' no existe.", exception.getMessage());
    }

    @Test
    @DisplayName("Debería devolver los atributos del rol cuando existen")
    void getRoleAttributes_Success() {

        Map<String, List<String>> attrs = new HashMap<>();
        attrs.put("scopes", List.of("READ", "WRITE"));
        attrs.put("owner", List.of("platform"));

        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        roleRep.setAttributes(attrs);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        Map<String, List<String>> result = roleService.getRoleAttributes(realm, testRole);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(List.of("READ", "WRITE"), result.get("scopes"));
        assertEquals(List.of("platform"), result.get("owner"));

        verify(rolesResource, times(1)).get(testRole);
        verify(roleResource, times(1)).toRepresentation();
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si el rol no tiene atributos (null)")
    void getRoleAttributes_ShouldThrow_WhenAttributesNull() {

        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        roleRep.setAttributes(null);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> roleService.getRoleAttributes(realm, testRole));

        assertTrue(ex.getMessage().contains("no tien atributos."));

        verify(roleResource, times(1)).toRepresentation();
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si el rol no tiene atributos (mapa vacío)")
    void getRoleAttributes_ShouldThrow_WhenAttributesEmpty() {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        roleRep.setAttributes(Collections.emptyMap()); // vacío

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> roleService.getRoleAttributes(realm, testRole));

        assertTrue(ex.getMessage().contains("no tien atributos."));
    }


    @Test
    @DisplayName("Debería añadir o actualizar atributos de rol exitosamente")
    void addOrUpdateRoleAttributes_Success() {
        RoleRepresentation roleRepresentation = new RoleRepresentation();
        roleRepresentation.setName(testRole);
        roleRepresentation.setAttributes(new HashMap<>());

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRepresentation);

        Map<String, List<String>> newAttributes = new HashMap<>();
        newAttributes.put("key1", List.of("value1"));

        assertDoesNotThrow(() -> roleService.addOrUpdateRoleAttributes(realm, testRole, newAttributes));

        verify(roleResource, times(1)).update(any(RoleRepresentation.class));
    }

    @Test
    @DisplayName("Debería lanzar excepción si los atributos están vacíos")
    void addOrUpdateRoleAttributes_EmptyAttributes() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                roleService.addOrUpdateRoleAttributes(realm, testRole, new HashMap<>())
        );

        assertTrue(exception.getMessage().contains("no puede estar vacío"));
    }

    @Test
    @DisplayName("Debería lanzar RuntimeException si el rol no existe (role es null)")
    void addOrUpdateRoleAttributes_ShouldThrow_WhenRoleIsNull() {
        Map<String, List<String>> newAttributes = Map.of("perm", List.of("READ"));

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(null);

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> roleService.addOrUpdateRoleAttributes(realm, testRole, newAttributes));

        assertEquals("Rol no encontrado: " + testRole, ex.getMessage());

        verify(roleResource, times(1)).toRepresentation();
    }

    @Test
    @DisplayName("Debería inicializar atributos si el rol no tiene ninguno (null)")
    void addOrUpdateRoleAttributes_ShouldInitializeAttributes_WhenExistingNull() {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        roleRep.setAttributes(null);

        Map<String, List<String>> newAttributes = Map.of("scope", List.of("WRITE"));

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        roleService.addOrUpdateRoleAttributes(realm, testRole, newAttributes);

        assertNotNull(roleRep.getAttributes());
        assertTrue(roleRep.getAttributes().containsKey("scope"));
        assertEquals(List.of("WRITE"), roleRep.getAttributes().get("scope"));

        verify(roleResource, times(1)).update(roleRep);
    }

    @Test
    @DisplayName("Debería eliminar atributo exitosamente cuando existe")
    void removeRoleAttribute_Success() {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        Map<String, List<String>> attrs = new HashMap<>();
        attrs.put("scope", List.of("READ", "WRITE"));
        roleRep.setAttributes(attrs);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        assertDoesNotThrow(() -> roleService.removeRoleAttribute(realm, testRole, "scope"));

        assertFalse(roleRep.getAttributes().containsKey("scope"));
        verify(roleResource, times(1)).update(roleRep);
    }

    @Test
    @DisplayName("Debería lanzar excepción cuando atributos es null")
    void removeRoleAttribute_ShouldThrow_WhenAttributesNull() {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        roleRep.setAttributes(null);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> roleService.removeRoleAttribute(realm, testRole, "scope"));

        assertEquals("El atributo 'scope' no existe en el rol 'ADMIN_ROLE' del realm 'plexus'.", ex.getMessage());
    }

    @Test
    @DisplayName("Debería lanzar excepción cuando el atributo no existe en el mapa")
    void removeRoleAttribute_ShouldThrow_WhenAttributeNotPresent() {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(testRole);
        Map<String, List<String>> attrs = new HashMap<>();
        attrs.put("owner", List.of("platform"));
        roleRep.setAttributes(attrs);

        when(utilsService.getRealmResource(anyString())).thenReturn(realmResource);
        when(realmResource.roles()).thenReturn(rolesResource);
        when(rolesResource.get(testRole)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(roleRep);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> roleService.removeRoleAttribute(realm, testRole, "scope"));

        assertEquals("El atributo 'scope' no existe en el rol 'ADMIN_ROLE' del realm 'plexus'.", ex.getMessage());
    }

}
