package br.com.rivaia.auth.security;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Publica a chave pública usada para assinar os tokens (formato JWK Set).
 * Os demais serviços da RivaIA apontam para esta URL para validar o JWT.
 */
@RestController
@Tag(name = "JWKS", description = "Chave pública para validação dos tokens")
public class JwksController {

    private final RSAKey rsaKey;

    public JwksController(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    @Operation(summary = "Chave pública (JWK Set) para validar tokens emitidos por este serviço")
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return new JWKSet(rsaKey.toPublicJWK()).toJSONObject();
    }
}
