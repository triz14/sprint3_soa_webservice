package br.com.rivaia.auth;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

@DisplayName("Autenticação: cadastro e login")
class AuthApiTest extends ApiTestSupport {

    @Test
    @DisplayName("POST /auth/register cria usuário USER, retorna 201 + Location e não expõe senha")
    void registerCreatesUser() throws Exception {
        String email = uniqueEmail();
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Bia", "email": "%s", "password": "%s"}
                                """.formatted(email, DEFAULT_PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(header().string(HttpHeaders.LOCATION, containsString("/api/v1/users/")))
                .andExpect(jsonPath("$.id").value(notNullValue()))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    @DisplayName("POST /auth/register com e-mail repetido retorna 409")
    void registerDuplicateEmail() throws Exception {
        String email = uniqueEmail();
        register(email, DEFAULT_PASSWORD);

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Outra", "email": "%s", "password": "%s"}
                                """.formatted(email.toUpperCase(), DEFAULT_PASSWORD)))
                .andExpect(status().isConflict())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    @DisplayName("POST /auth/register com dados inválidos retorna 400 com erros por campo")
    void registerInvalidPayload() throws Exception {
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "", "email": "nao-e-email", "password": "123"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.instance").value("/api/v1/auth/register"))
                .andExpect(jsonPath("$.errors.length()").value(3));
    }

    @Test
    @DisplayName("POST /auth/register com JSON malformado retorna 400")
    void registerMalformedJson() throws Exception {
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ isso não é json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /auth/login com credenciais corretas retorna 200 e token Bearer")
    void loginReturnsToken() throws Exception {
        String email = uniqueEmail();
        register(email, DEFAULT_PASSWORD);

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "%s"}
                                """.formatted(email, DEFAULT_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value(notNullValue()))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(greaterThan(0)))
                .andExpect(jsonPath("$.expiresAt").value(notNullValue()));
    }

    @Test
    @DisplayName("POST /auth/login com senha errada retorna 401")
    void loginWrongPassword() throws Exception {
        String email = uniqueEmail();
        register(email, DEFAULT_PASSWORD);

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "senha-errada"}
                                """.formatted(email)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("POST /auth/login com e-mail inexistente retorna 401 (mesma resposta da senha errada)")
    void loginUnknownEmail() throws Exception {
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "%s"}
                                """.formatted(uniqueEmail(), DEFAULT_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /auth/login de conta desativada pelo ADMIN retorna 403")
    void loginDisabledAccount() throws Exception {
        String email = uniqueEmail();
        long id = register(email, DEFAULT_PASSWORD);

        mvc.perform(put("/api/v1/users/{id}", id)
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Usuário Teste", "email": "%s", "role": "USER", "active": false}
                                """.formatted(email)))
                .andExpect(status().isOk());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "%s"}
                                """.formatted(email, DEFAULT_PASSWORD)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
    }
}
