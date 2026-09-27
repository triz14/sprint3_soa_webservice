package br.com.rivaia.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import com.jayway.jsonpath.JsonPath;

@DisplayName("Usuários (ADMIN): controle de acesso por perfil e CRUD")
class AdminUsersApiTest extends ApiTestSupport {

    @Test
    @DisplayName("USER tentando listar usuários recebe 403")
    void userCannotList() throws Exception {
        mvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(newUserToken())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @DisplayName("USER tentando excluir outro usuário recebe 403")
    void userCannotDelete() throws Exception {
        long victim = register(uniqueEmail(), DEFAULT_PASSWORD);

        mvc.perform(delete("/api/v1/users/{id}", victim)
                        .header(HttpHeaders.AUTHORIZATION, bearer(newUserToken())))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Listar usuários sem token retorna 401")
    void listWithoutToken() throws Exception {
        mvc.perform(get("/api/v1/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("ADMIN lista usuários com paginação (200)")
    void adminLists() throws Exception {
        mvc.perform(get("/api/v1/users").param("page", "0").param("size", "5")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(5))
                .andExpect(jsonPath("$.totalElements").exists());
    }

    @Test
    @DisplayName("Parâmetro de paginação fora do limite retorna 400")
    void invalidPageSize() throws Exception {
        mvc.perform(get("/api/v1/users").param("size", "1000")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken())))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("ADMIN: POST 201 → GET 200 → PUT 200 → DELETE 204 → GET 404")
    void adminCrudFlow() throws Exception {
        String admin = bearer(adminToken());
        String email = uniqueEmail();

        var created = mvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Gestor", "email": "%s", "password": "%s", "role": "USER"}
                                """.formatted(email, DEFAULT_PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("USER"))
                .andReturn();
        long id = ((Number) JsonPath.read(body(created), "$.id")).longValue();
        assertThat(created.getResponse().getHeader(HttpHeaders.LOCATION))
                .endsWith("/api/v1/users/" + id);

        mvc.perform(get("/api/v1/users/{id}", id).header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));

        mvc.perform(put("/api/v1/users/{id}", id)
                        .header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Gestor Promovido", "email": "%s", "role": "ADMIN", "active": true}
                                """.formatted(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Gestor Promovido"))
                .andExpect(jsonPath("$.role").value("ADMIN"));

        mvc.perform(delete("/api/v1/users/{id}", id).header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(status().isNoContent());

        mvc.perform(get("/api/v1/users/{id}", id).header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    @Test
    @DisplayName("Usuário promovido a ADMIN ganha acesso aos endpoints administrativos após novo login")
    void promotedUserGetsAdminAccess() throws Exception {
        String email = uniqueEmail();
        long id = register(email, DEFAULT_PASSWORD);

        mvc.perform(put("/api/v1/users/{id}", id)
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Novo Admin", "email": "%s", "role": "ADMIN", "active": true}
                                """.formatted(email)))
                .andExpect(status().isOk());

        mvc.perform(get("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(login(email, DEFAULT_PASSWORD))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("ADMIN criando usuário com e-mail existente recebe 409")
    void adminCreateDuplicate() throws Exception {
        mvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Dup", "email": "%s", "password": "%s", "role": "USER"}
                                """.formatted(ADMIN_EMAIL, DEFAULT_PASSWORD)))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("ADMIN criando usuário sem perfil recebe 400")
    void adminCreateWithoutRole() throws Exception {
        mvc.perform(post("/api/v1/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Sem Perfil", "email": "%s", "password": "%s"}
                                """.formatted(uniqueEmail(), DEFAULT_PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].field").value("role"));
    }

    @Test
    @DisplayName("GET /users/{id} inexistente retorna 404")
    void getUnknown() throws Exception {
        mvc.perform(get("/api/v1/users/{id}", 999_999).header(HttpHeaders.AUTHORIZATION, bearer(adminToken())))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /users/{id} com id não numérico retorna 400")
    void getInvalidId() throws Exception {
        mvc.perform(get("/api/v1/users/abc").header(HttpHeaders.AUTHORIZATION, bearer(adminToken())))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("ADMIN não pode excluir a própria conta (409)")
    void adminCannotDeleteSelf() throws Exception {
        String admin = bearer(adminToken());
        var me = mvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(status().isOk())
                .andReturn();
        long adminId = ((Number) JsonPath.read(body(me), "$.id")).longValue();

        mvc.perform(delete("/api/v1/users/{id}", adminId).header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("Método HTTP não suportado no recurso retorna 405")
    void methodNotAllowed() throws Exception {
        mvc.perform(delete("/api/v1/users").header(HttpHeaders.AUTHORIZATION, bearer(adminToken())))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().exists(HttpHeaders.CONTENT_TYPE));
    }
}
