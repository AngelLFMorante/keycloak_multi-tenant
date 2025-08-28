package com.example.keycloak.multitenant.service.utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class DataConversionUtilsServiceTest {

    @InjectMocks
    private DataConversionUtilsService service;

    @Test
    @DisplayName("getSafeString: Deberia devolver el valor String correcto para una clave valida")
    void getSafeString_shouldReturnString_whenKeyExistsAndIsString() {
        Map<String, Object> map = new HashMap<>();
        map.put("name", "John Doe");
        map.put("age", 30);

        String result = service.getSafeString(map, "name");

        assertEquals("John Doe", result);
    }

    @Test
    @DisplayName("getSafeString: Deberia devolver null si el valor no es un String")
    void getSafeString_shouldReturnNull_whenValueIsNotString() {
        Map<String, Object> map = new HashMap<>();
        map.put("age", 30);

        String result = service.getSafeString(map, "age");

        assertNull(result);
    }

    @Test
    @DisplayName("getSafeString: Deberia devolver null si la clave no existe en el mapa")
    void getSafeString_shouldReturnNull_whenKeyDoesNotExist() {
        Map<String, Object> map = new HashMap<>();
        map.put("age", 30);

        String result = service.getSafeString(map, "name");

        assertNull(result);
    }

    @Test
    @DisplayName("getSafeString: Deberia devolver null si el mapa es nulo")
    void getSafeString_shouldReturnNull_whenMapIsNull() {
        Map<String, Object> map = null;

        String result = service.getSafeString(map, "name");

        assertNull(result);
    }

    @Test
    @DisplayName("getSafeString: Deberia devolver null si la clave es nula")
    void getSafeString_shouldReturnNull_whenKeyIsNull() {
        Map<String, Object> map = new HashMap<>();
        map.put("name", "John Doe");

        String result = service.getSafeString(map, null);

        assertNull(result);
    }

    @Test
    @DisplayName("getSafeString: Deberia devolver null si el mapa esta vacio")
    void getSafeString_shouldReturnNull_whenMapIsEmpty() {
        Map<String, Object> map = new HashMap<>();

        String result = service.getSafeString(map, "name");

        assertNull(result);
    }

    @Test
    @DisplayName("getSafeList: Deberia devolver la lista de Strings correcta")
    void getSafeList_shouldReturnList_whenValueIsListOfStrings() {
        Map<String, Object> map = new HashMap<>();
        map.put("roles", List.of("user", "admin"));

        List<String> result = service.getSafeList(map, "roles");

        assertEquals(2, result.size());
        assertTrue(result.contains("user"));
        assertTrue(result.contains("admin"));
    }

    @Test
    @DisplayName("getSafeList: Deberia envolver un solo String en una lista")
    void getSafeList_shouldWrapStringInList_whenValueIsSingleString() {
        Map<String, Object> map = new HashMap<>();
        map.put("role", "user");

        List<String> result = service.getSafeList(map, "role");

        assertEquals(1, result.size());
        assertEquals("user", result.get(0));
    }

    @Test
    @DisplayName("getSafeList: Deberia devolver una lista vacia si el valor no es una lista o String")
    void getSafeList_shouldReturnEmptyList_whenValueIsIncorrectType() {
        Map<String, Object> map = new HashMap<>();
        map.put("permissions", 123);

        List<String> result = service.getSafeList(map, "permissions");

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("getSafeList: Deberia devolver una lista vacia si la clave no existe")
    void getSafeList_shouldReturnEmptyList_whenKeyDoesNotExist() {
        Map<String, Object> map = new HashMap<>();

        List<String> result = service.getSafeList(map, "roles");

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("getSafeList: Deberia devolver una lista vacia si el mapa es nulo")
    void getSafeList_shouldReturnEmptyList_whenMapIsNull() {
        Map<String, Object> map = null;

        List<String> result = service.getSafeList(map, "roles");

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("getSafeList: Deberia devolver una lista vacia si la clave es nula")
    void getSafeList_shouldReturnEmptyList_whenKeyIsNull() {
        Map<String, Object> map = new HashMap<>();
        map.put("roles", List.of("user", "admin"));

        List<String> result = service.getSafeList(map, null);

        assertTrue(result.isEmpty());
    }
}
