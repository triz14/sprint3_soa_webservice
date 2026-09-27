package br.com.rivaia.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

/**
 * Base dos testes de integração: sobe a aplicação inteira (segurança, JWT,
 * JPA) com banco H2 em memória e faz requisições HTTP reais via MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class ApiTestSupport {

    protected static final String ADMIN_EMAIL = "admin@test.com";
    protected static final String ADMIN_PASSWORD = "Admin@12345";
    protected static final String DEFAULT_PASSWORD = "Senha@1234";

    @Autowired
    protected MockMvc mvc;

    protected static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@test.com";
    }

    protected static String bearer(String token) {
        return "Bearer " + token;
    }

    protected static String body(org.springframework.test.web.servlet.MvcResult result) throws Exception {
        return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** Cadastra um USER pelo endpoint público e devolve o id criado. */
    protected long register(String email, String password) throws Exception {
        String json = """
                {"name": "Usuário Teste", "email": "%s", "password": "%s"}
                """.formatted(email, password);
        var result = mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn();
        return ((Number) JsonPath.read(body(result), "$.id")).longValue();
    }

    protected String login(String email, String password) throws Exception {
        String json = """
                {"email": "%s", "password": "%s"}
                """.formatted(email, password);
        var result = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andReturn();
        return JsonPath.read(body(result), "$.accessToken");
    }

    protected String adminToken() throws Exception {
        return login(ADMIN_EMAIL, ADMIN_PASSWORD);
    }

    /** Cria um USER novo e devolve o token dele. */
    protected String newUserToken() throws Exception {
        String email = uniqueEmail();
        register(email, DEFAULT_PASSWORD);
        return login(email, DEFAULT_PASSWORD);
    }
}
