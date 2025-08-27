package com.example.keycloak.multitenant.service.utils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Servicio de utilidad para la conversion y extraccion segura de datos
 * desde estructuras de datos genericas como {@link Map}.
 * <p>
 * Provee metodos para evitar errores de {@link ClassCastException} al
 * trabajar con datos cuyo tipo no esta garantizado.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class DataConversionUtilsService {

    private static final Logger log = LoggerFactory.getLogger(DataConversionUtilsService.class);

    /**
     * Extrae un valor {@link String} de forma segura de un {@link Map}
     * basándose en una clave.
     * <p>
     * Este metodo previene {@link ClassCastException} al verificar si el
     * valor asociado a la clave es una instancia de {@link String}.
     *
     * @param map El mapa de origen que contiene los datos.
     * @param key La clave del mapa para buscar el valor.
     * @return El valor como un String si la clave existe y el valor es un String,
     * de lo contrario, retorna {@code null}.
     */
    public String getSafeString(Map<String, Object> map, String key) {
        log.debug("Intentando obtener un valor String de la clave '{}'.", key);
        if (map == null || key == null || map.isEmpty()) {
            log.warn("El mapa o la clave son nulos o el mapa esta vacio. Retornando null.");
            return null;
        }

        Object value = map.get(key);
        if (value instanceof String) {
            log.debug("Valor encontrado para la clave '{}'.", key);
            return (String) value;
        }

        log.debug("No se encontro un valor String para la clave '{}' o el tipo no coincide. Valor: {}", key, value != null ? value.getClass().getName() : "null");
        return null;
    }

    /**
     * Extrae una {@link List} de {@link String} de forma segura de un {@link Map}.
     * <p>
     * Este metodo es robusto y maneja dos casos:
     * <ul>
     * <li>Si el valor es directamente una {@link List}, lo convierte y devuelve.</li>
     * <li>Si el valor es un solo {@link String}, lo envuelve en una lista de un solo elemento.</li>
     * </ul>
     * Si el valor no es ni una lista ni un string, o si el mapa es nulo,
     * retorna una lista vacia para evitar {@link NullPointerException}.
     *
     * @param map El mapa de origen que contiene los datos.
     * @param key La clave del mapa para buscar la lista.
     * @return Una {@link List} de Strings si se encuentra, o una lista vacia en caso contrario.
     */
    public List<String> getSafeList(Map<String, Object> map, String key) {
        log.debug("Intentando obtener una lista de Strings de la clave '{}'.", key);
        if (map == null || key == null || map.isEmpty()) {
            log.warn("El mapa o la clave son nulos o el mapa esta vacio. Retornando lista vacia.");
            return Collections.emptyList();
        }

        Object value = map.get(key);
        if (value instanceof List) {
            log.debug("Se encontro una lista para la clave '{}'.", key);
            try {
                return (List<String>) value;
            } catch (ClassCastException e) {
                log.error("El valor para la clave '{}' es una lista, pero contiene elementos que no son de tipo String. Retornando lista vacia.", key, e);
                return Collections.emptyList();
            }
        } else if (value instanceof String) {
            log.debug("Se encontro un solo String para la clave '{}', envolviendolo en una lista.", key);
            return Collections.singletonList((String) value);
        }

        log.debug("No se encontro una lista o String para la clave '{}'. Retornando lista vacia. Valor: {}", key, value != null ? value.getClass().getName() : "null");
        return Collections.emptyList();
    }
}
