package com.example.keycloak.multitenant.service.utils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class DataConversionUtilsService {

    /**
     * Obtiene un String de forma segura desde un Map.
     */
    public String getSafeString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof String) {
            return (String) value;
        }
        return null;
    }

    /**
     * Obtiene una List<String> de forma segura desde un Map, manejando Strings o Listas.
     */
    public List<String> getSafeList(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof List) {
            return (List<String>) value;
        } else if (value instanceof String) {
            return Collections.singletonList((String) value);
        }
        return Collections.emptyList();
    }
}
