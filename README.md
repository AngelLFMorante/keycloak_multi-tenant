[![Java](https://img.shields.io/badge/Java-17-007396?style=flat\&logo=java\&logoColor=white)](https://www.java.com/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3-6DB33F?style=flat\&logo=spring-boot\&logoColor=white)](https://spring.io/projects/spring-boot)
[![Keycloak](https://img.shields.io/badge/Keycloak-22+-7C3AED?style=flat\&logo=keycloak\&logoColor=white)](https://www.keycloak.org/)
[![Postman](https://img.shields.io/badge/Postman-FF6C37?style=flat\&logo=postman\&logoColor=white)](https://www.postman.com/)
[![Swagger](https://img.shields.io/badge/Swagger-3-85EA2D?style=flat\&logo=swagger)](https://swagger.io/)
[![Docker](https://img.shields.io/badge/Docker-Container_Ready-2496ED?style=flat\&logo=docker\&logoColor=white)](https://www.docker.com/)

# Microservicio de Autenticación con Spring Boot y Keycloak

**Microservicio de Autenticación** es una API REST desarrollada con **Spring Boot** que permite gestionar el login de usuarios mediante Keycloak con soporte multi-realm. Proporciona endpoints para login, logout, registro y gestión de sesiones, todo centralizado y extensible.

## 📌 Objetivo

* Gestionar usuarios mediante Keycloak Admin Client.
* Permitir login y registro desde múltiples realms.
* Mantener sesiones activas y válidas entre Keycloak y el backend.
* Registrar errores de red, validación, y seguridad de manera estructurada.

## 🛠️ Tecnologías Usadas

* **Java 17**
* **Spring Boot 3.x**
* **Spring Security** con configuración personalizada
* **Keycloak 22+** con clientes confidenciales
* **Keycloak Admin Client SDK**
* **Docker** y **Docker Compose** para orquestación
* **RestTemplate** para comunicación con Keycloak
* **SLF4J + Logback** para logs
* **Swagger/OpenAPI** para documentación REST

## 🚀 Cómo Ejecutar el Proyecto

### 1. Clonar el Repositorio

```bash
  git clone https://github.com/AngelLFMorante/keycloak_multi-tenant
  cd tu-repo
```

### 2. Levantar Keycloak con Docker (modo desarrollo y persistencia)

```bash
    docker run -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    -v keycloak_data:/opt/keycloak/data \
    quay.io/keycloak/keycloak:latest start-dev
```

Esto levantará Keycloak en http://localhost:8080 con persistencia de datos gracias al volumen keycloak_data.

### 3. Crear Realm y Configuraciones en Keycloak

Accede a `http://localhost:8080` con:

* **usuario**: `admin`
* **contraseña**: `admin`

Luego:

* Crea un **Realm**: `demo-realm`
* Crea un **Cliente**: `demo-client`
* Agrega URL de redirección: `http://localhost:8081/*`
* Crea **roles**: `user`, `admin`
* Crea un **usuario**: `angel` / `1234`, con rol `user`

### ⚙️ Configuración de `application.properties`

```properties
  keycloak.auth-server-url=http://localhost:8080
  keycloak.admin.realm=master
  keycloak.admin.username=admin
  keycloak.admin.password=admin
  keycloak.admin.client-id=admin-cli
```

## ▶️ Ejecutar la Aplicación

```bash
  ./mvnw spring-boot:run
```

O usando Docker:

```bash
  docker build -t spring-auth-service .
  docker run -p 8081:8081 --name keycloak-demo-container keycloak-demo-app
```

## 🔐 Endpoints Disponibles

| Método | Endpoint                     | Descripción                     |
| ------ | ---------------------------- | ------------------------------- |
| GET    | `/{realm}/login`             | Página de login                 |
| POST   | `/{realm}/{client}/do_login` | Login con usuario/password      |
| POST   | `/{realm}/register`          | Registro de usuario en Keycloak |
| GET    | `/logout`                    | Logout y cierre de sesión       |
| GET    | `/swagger-ui/index.html`     | Acceso a Swagger UI             |

## 🧪 Postman cURL's de Ejemplo

### 🔑 Login

```bash
  curl -X POST \
  http://localhost:8081/{REALM_PATH}/{CLIENT_ID}/do_login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username={USERNAME}&password={PASSWORD}'
```

### 🧍 Registro

```bash
  curl -X POST \
  http://localhost:8081/{REALM_PATH}/register \
  -H 'Content-Type: application/json' \
  -d '{
        "username": "{NEW_USERNAME}",
        "email": "{NEW_EMAIL}",
        "password": "{NEW_PASSWORD}",
        "confirmPassword": "{NEW_PASSWORD}"
      }'
```

## 🧯 Manejo de Errores

* `ResourceAccessException` → errores de red
* `HttpClientErrorException` / `HttpServerErrorException` → errores HTTP
* Validaciones (`@Valid`) y errores personalizados
* Excepciones generales y de Keycloak (duplicados, estados inválidos)

## 🔐 Seguridad de la Aplicación

* Login multi-realm
* Logout bidireccional (Keycloak + backend)
* Máxima 1 sesión activa por usuario
* Rutas públicas permitidas: `/public`, `/swagger-ui`, `/v3/api-docs/**`
* Password dummy no valida credenciales reales

## 🧠 Cómo Funciona la Aplicación

### 🏷️ Multi-tenant: Realms y Clients dinámicos

La aplicación soporta múltiples **realms** y **clients** configurables a través del archivo `application.properties`. Esto permite enrutar y validar las credenciales de los usuarios contra distintos entornos Keycloak de forma dinámica.

#### 🔁 Realms dinámicos

Se define un mapeo donde el segmento de URL (por ejemplo, `demo`) se asocia a un nombre real del realm en Keycloak:

```properties
keycloak.realm-mapping.plexus=plexus-realm
keycloak.realm-mapping.inditex=inditex-realm
```

Así, una petición a `http://localhost:8081/plexus/login` será tratada como perteneciente al realm `plexus-realm` en Keycloak.

#### 🔑 Clients y Secrets por Realm

Cada realm tiene su propio cliente configurado. En `application.properties`, se declaran los `client-id` y sus `client-secrets`:

```properties
keycloak.client-secrets.mi-app-plexus=<<secret>>
keycloak.client-secrets.mi-app-inditex=<<secret>>
```

Cuando un usuario intenta hacer login desde un endpoint como:

```
POST /plexus/mi-app-plexus/do_login
```

La aplicación busca en `application.properties` el secreto para `mi-app-plexus` y lo utiliza para comunicarse con el realm `plexus-realm`.

Estas asociaciones deben existir previamente en el archivo de configuración y deben coincidir con los valores reales configurados en Keycloak.

* Autenticación centralizada mediante Keycloak.
* Gestión de usuarios vía Keycloak Admin Client.
* Configuración de múltiples realms desde `application.properties`.
* Manejo estructurado de excepciones, tokens, sesiones y logout.

## ✅ Pruebas Unitarias

Ejecuta:

```bash
  mvn test
```

## 👤 Autor

**Angel L. Fernandez Morante**

## 📝 Licencia

MIT
