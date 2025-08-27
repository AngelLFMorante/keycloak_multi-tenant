package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Date;

/**
 * Record que representa una estructura estandar para las respuestas de error de la API.
 * <p>
 * Este objeto encapsula informacion clave sobre un error HTTP, incluyendo
 * la fecha, el codigo de estado, un mensaje descriptivo y detalles adicionales
 * que pueden ser utiles para la depuracion.
 *
 * @param timestamp La fecha y hora exactas en que ocurrio el error.
 * @param status    El codigo de estado HTTP del error (ej. 400, 404, 500).
 * @param error     Una descripcion breve del error HTTP (ej. "Bad Request", "Not Found").
 * @param message   Un mensaje detallado que explica la causa del error.
 * @param details   Un objeto opcional que puede contener informacion adicional sobre
 *                  errores de validacion, como un mapa de campos y sus respectivos mensajes de error.
 * @author Angel Fm
 * @version 1.0
 */
@Schema(description = "Estructura estandar para las respuestas de error de la API.")
public record ErrorResponse(
        @Schema(description = "Fecha y hora en que ocurrio el error.", example = "2023-10-27T10:30:00.000+00:00")
        Date timestamp,

        @Schema(description = "Codigo de estado HTTP del error.", example = "400")
        int status,

        @Schema(description = "Descripcion del error HTTP.", example = "Bad Request")
        String error,

        @Schema(description = "Mensaje detallado del error.", example = "Uno o mas campos tienen errores de validacion.")
        String message,

        @Schema(description = "Detalles adicionales sobre los errores de validacion.", example = "{ 'username': 'El nombre de usuario no puede estar vacio' }")
        Object details
) {
}