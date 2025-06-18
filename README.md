-----

# Keycloak Demo Application

This application showcases a robust multi-tenant authentication system built with **Spring Boot** and **Keycloak**. It's designed to seamlessly handle user authentication for different "tenants" (like "plexus" and "inditex"), each with their own dedicated home page and authentication flow, all managed through dynamic client registration with Keycloak.

-----

## 🚀 Getting Started

This guide will walk you through setting up and running both Keycloak (via Docker) and the Spring Boot application.

### Prerequisites

Before you begin, ensure you have the following installed:

* **Docker:** For running the Keycloak server.
* **Java 17 or higher:** To run the Spring Boot application.
* **Maven:** For building and managing the Spring Boot project.

-----

## 🛠️ Technologies Used

* **Keycloak:** Open Source Identity and Access Management

  [](https://www.keycloak.org/)

* **Spring Boot:** A powerful Java-based framework for creating stand-alone, production-grade Spring applications with minimal configuration.

  [](https://spring.io/)

* **Java:** The core programming language used for the backend application.

  [](https://www.oracle.com/java/)

* **Maven:** A dependency management and build automation tool for Java projects.

  [](https://maven.apache.org/)

* **Thymeleaf:** A server-side Java template engine used for rendering dynamic HTML content in the web views.

  [](https://www.thymeleaf.org/)

* **Bootstrap:** A popular CSS framework used for developing responsive and mobile-first front-end web development.

  [](https://getbootstrap.com/)

-----

## ⚙️ How it Works

This application implements a multi-tenant architecture by leveraging Keycloak's flexible realm and client configurations.

* **Dynamic Client Registration:** The core of the multi-tenancy lies in the `DynamicClientRegistrationRepository`. This custom component intercepts authentication requests and dynamically configures the OAuth2 client for **Spring Security** based on the tenant identified in the URL (e.g., `/plexus/login`, `/inditex/login`). This means you don't need to hardcode client registrations for every tenant in your `application.properties`.
* **Tenant-Specific Realms:** Each tenant (e.g., "plexus", "inditex") is mapped to its own **Keycloak Realm**, allowing for isolated user management, roles, and authentication policies.
* **Custom Authentication Success Handler:** After a successful login, the `CustomAuthenticationSuccessHandler` redirects the user to their specific tenant's home page (e.g., `/{tenant}/home`), providing a personalized experience.
* **Role Extraction:** The `oidcUserService` is customized to extract user roles from both `realm_access` and `resource_access` claims within the **Keycloak** ID Token, ensuring granular authorization within the application.
* **Logout Handling:** A custom `LogoutSuccessHandler` ensures that users are properly logged out from **Keycloak** as well, invalidating their session and redirecting them back to the application's root.

-----

## 🚀 Running the Application

Follow these steps to get the application up and running:

### 1\. Start Keycloak with Docker

First, launch your Keycloak instance using Docker. This command will start Keycloak, expose it on port `8080`, and set up an initial administrator user. The `-v keycloak_data:/opt/keycloak/data` part ensures that your Keycloak data (realms, users, clients) persists even if you stop and restart the container.

```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -v keycloak_data:/opt/keycloak/data quay.io/keycloak/keycloak:latest start-dev
```

Once Keycloak is running, access its administration console at `http://localhost:8080` and log in with the `admin` credentials you set (`admin`/`admin`).

**Keycloak Configuration Steps:**

* **Create Realms:** Create two new realms: `plexus-realm` and `inditex-realm`.
* **Create Clients:** Within each realm, create a client:
    * For `plexus-realm`: Create a client with `Client ID` `mi-app-plexus`.
    * For `inditex-realm`: Create a client with `Client ID` `mi-app-inditex`.
* **Configure Client Settings:** For each client (`mi-app-plexus` and `mi-app-inditex`):
    * Set **Client authentication** to `On`.
    * Generate a **Client secret** (you'll need to update this in `DynamicClientRegistrationRepository.java` for the respective tenant, but for this demo, the hardcoded values are `APE7Jo7L22EY8yTKh50v6B82nQ8l3f24` for `plexus` and `5LR8rwO0VLFpog0lCrxrODfxlwQEEj7g` for `inditex`).
    * Add a **Valid redirect URIs** entry: `http://localhost:8081/login/oauth2/code/*`.
    * Set **Web origins** to `http://localhost:8081`.
* **Create Users:** Create users within each realm. For example, a user in `plexus-realm` and another in `inditex-realm`.

### 2\. Build and Run the Spring Boot Application

Navigate to the root directory of your Spring Boot project in the terminal.

```bash
# Build the application
mvn clean install

# Run the application
mvn spring-boot:run
```

The application will start on **port 8081** (as configured in `application.properties`).

-----

## 🌐 Accessing the Application

Open your web browser and navigate to `http://localhost:8081`. You will see the main landing page with options to log in to different tenants.

* **Login to Plexus:** Click on "Go to Plexus App (Requires Login)" or navigate directly to `http://localhost:8081/plexus/login`. You will be redirected to the **Keycloak** login page for `plexus-realm`.
* **Login to Inditex:** Click on "Go to Inditex App (Requires Login)" or navigate directly to `http://localhost:8081/inditex/login`. You will be redirected to the **Keycloak** login page for `inditex-realm`.

After successfully authenticating with **Keycloak**, you will be redirected to the respective tenant's home page (e.g., `http://localhost:8081/plexus/home`), displaying your user information and roles.

-----

## 🔚 Logging Out

From any tenant's home page, simply click the **"Logout"** button. This will initiate the **OAuth2** logout flow, redirecting you back to the application's public home page and ending your session in **Keycloak**.

-----
## 👤 Author

Ángel (Plexus)
