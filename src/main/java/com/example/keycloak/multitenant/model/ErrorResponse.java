package com.example.keycloak.multitenant.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Modelo estandar para las respuestas de error de la API.
 * Proporciona un formato consistente para que los clientes puedan manejar los errores de manera predecible.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Estructura estandar para las respuestas de error de la API.")
public class ErrorResponse {

    /**
     * Sello de tiempo que indica cuándo ocurrió el error.
     */
    @Schema(description = "Fecha y hora en que ocurrio el error.", example = "2023-10-27T10:30:00.000+00:00")
    private Date timestamp;

    /**
     * Codigo de estado HTTP del error (ej. 400, 404, 500).
     */
    @Schema(description = "Codigo de estado HTTP del error.", example = "400")
    private int status;

    /**
     * La razon del error HTTP (ej. "Bad Request", "Not Found").
     */
    @Schema(description = "Descripcion del error HTTP.", example = "Bad Request")
    private String error;

    /**
     * Mensaje detallado que explica la causa del error.
     */
    @Schema(description = "Mensaje detallado del error.", example = "Uno o mas campos tienen errores de validacion.")
    private String message;

    /**
     * Campo opcional para detalles adicionales, como los errores de validacion de campos.
     */
    @Schema(description = "Detalles adicionales sobre los errores de validacion.", example = "{ 'username': 'El nombre de usuario no puede estar vacio' }")
    private Object details;
}