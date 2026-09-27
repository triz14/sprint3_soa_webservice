package br.com.rivaia.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.RSAKey;

@DisplayName("JWT: geração, validação, expiração e endpoints públicos")
class TokenSecurityTest extends ApiTestSupport {

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private RSAKey rsaKey;

    @Test
    @DisplayName("Endpoint protegido sem token retorna 401 em formato padronizado")
    void withoutToken() throws Exception {
        mvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.instance").value("/api/v1/users/me"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    @DisplayName("Token válido dá acesso e o usuário é identificado pelo claim sub")
    void validToken() throws Exception {
        String email = uniqueEmail();
        long id = register(email, DEFAULT_PASSWORD);
        String token = login(email, DEFAULT_PASSWORD);

        mvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("Token contém os claims esperados (iss, sub, exp, roles)")
    void tokenClaims() throws Exception {
        String email = uniqueEmail();
        long id = register(email, DEFAULT_PASSWORD);
        String token = login(email, DEFAULT_PASSWORD);

        String payloadJson = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                StandardCharsets.UTF_8);

        assertThat((String) JsonPath.read(payloadJson, "$.iss"))
                .isEqualTo("rivaia-auth-service");
        assertThat((String) JsonPath.read(payloadJson, "$.sub"))
                .isEqualTo(String.valueOf(id));
        assertThat((List<String>) JsonPath.read(payloadJson, "$.roles"))
                .containsExactly("USER");
        assertThat((Object) JsonPath.read(payloadJson, "$.exp"))
                .isNotNull();
    }

    @Test
    @DisplayName("Token com assinatura adulterada retorna 401")
    void tamperedToken() throws Exception {
        String token = newUserToken();
        String[] parts = token.split("\\.");
        // troca o primeiro caractere da assinatura (bits significativos)
        char first = parts[2].charAt(0);
        String tampered = parts[0] + "." + parts[1] + "."
                + (first == 'A' ? 'B' : 'A') + parts[2].substring(1);

        mvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, bearer(tampered)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    }

    @Test
    @DisplayName("Token malformado retorna 401")
    void malformedToken() throws Exception {
        mvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, bearer("abc.def.ghi")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Token expirado retorna 401")
    void expiredToken() throws Exception {
        Instant now = Instant.now();
        String expired = signToken("rivaia-auth-service", now.minusSeconds(3600), now.minusSeconds(600));

        mvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, bearer(expired)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("Token de outro emissor (iss) retorna 401")
    void wrongIssuer() throws Exception {
        Instant now = Instant.now();
        String foreign = signToken("outro-emissor", now, now.plusSeconds(600));

        mvc.perform(get("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, bearer(foreign)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json é público e expõe só a chave pública")
    void jwksIsPublic() throws Exception {
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value(rsaKey.getKeyID()))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    @DisplayName("Documentação OpenAPI é pública")
    void openApiIsPublic() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openapi").exists());
    }

    @Test
    @DisplayName("Rota inexistente autenticada retorna 404 padronizado")
    void unknownRoute() throws Exception {
        mvc.perform(get("/api/v1/nao-existe").header(HttpHeaders.AUTHORIZATION, bearer(newUserToken())))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    private String signToken(String issuer, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("1")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("roles", List.of("ADMIN"))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(rsaKey.getKeyID()).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
