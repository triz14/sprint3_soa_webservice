package br.com.rivaia.auth.security;

import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

import br.com.rivaia.auth.config.JwtProperties;

/**
 * Chaves e componentes de assinatura/validação do JWT.
 *
 * <p>Os tokens são assinados com RS256 (chave assimétrica). A chave privada
 * fica só neste serviço; a pública é publicada em /.well-known/jwks.json para
 * que os outros serviços da RivaIA validem tokens sem compartilhar segredo.
 *
 * <p>O par de chaves é gerado na inicialização. Ao reiniciar o serviço, os
 * tokens antigos deixam de valer e os usuários precisam logar de novo.
 */
@Configuration
public class JwtKeyConfig {

    @Bean
    public RSAKey rsaKey() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Não foi possível gerar a chave RSA do JWT", e);
        }
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey rsaKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
    }

    /**
     * Valida assinatura, expiração (exp/nbf) e emissor (iss) de cada token recebido.
     */
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey, JwtProperties props) {
        RSAPublicKey publicKey;
        try {
            publicKey = rsaKey.toRSAPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("Chave pública RSA inválida", e);
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(props.issuer()));
        return decoder;
    }
}
