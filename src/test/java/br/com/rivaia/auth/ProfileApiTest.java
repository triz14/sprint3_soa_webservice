package br.com.rivaia.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

@DisplayName("Meu perfil: operações do usuário autenticado")
class ProfileApiTest extends ApiTestSupport {

    @Test
    @DisplayName("PUT /users/me atualiza nome e e-mail do dono do token")
    void updateProfile() throws Exception {
        String token = newUserToken();
        String newEmail = uniqueEmail();

        mvc.perform(put("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Nome Novo", "email": "%s"}
                                """.formatted(newEmail)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Nome Novo"))
                .andExpect(jsonPath("$.email").value(newEmail))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("PUT /users/me com e-mail de outro usuário retorna 409")
    void updateProfileEmailConflict() throws Exception {
        String token = newUserToken();

        mvc.perform(put("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "Qualquer", "email": "%s"}
                                """.formatted(ADMIN_EMAIL)))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("PUT /users/me sem token retorna 401")
    void updateProfileWithoutToken() throws Exception {
        mvc.perform(put("/api/v1/users/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name": "X", "email": "x@test.com"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PUT /users/me/password troca a senha (204) e a nova senha passa a valer no login")
    void changePassword() throws Exception {
        String email = uniqueEmail();
        register(email, DEFAULT_PASSWORD);
        String token = login(email, DEFAULT_PASSWORD);

        mvc.perform(put("/api/v1/users/me/password")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword": "%s", "newPassword": "NovaSenha@2026"}
                                """.formatted(DEFAULT_PASSWORD)))
                .andExpect(status().isNoContent());

        login(email, "NovaSenha@2026");

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "%s"}
                                """.formatted(email, DEFAULT_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PUT /users/me/password com senha atual errada retorna 400")
    void changePasswordWrongCurrent() throws Exception {
        String token = newUserToken();

        mvc.perform(put("/api/v1/users/me/password")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword": "errada123", "newPassword": "NovaSenha@2026"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }
}
