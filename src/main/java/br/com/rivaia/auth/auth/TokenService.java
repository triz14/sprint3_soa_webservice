package br.com.rivaia.auth.auth;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.jwk.RSAKey;

import br.com.rivaia.auth.config.JwtProperties;
import br.com.rivaia.auth.security.SecurityConfig;
import br.com.rivaia.auth.user.User;

/**
 * Gera o access token JWT.
 *
 * <p>Claims emitidos:
 * <ul>
 *   <li>iss: emissor (validado pelos consumidores)</li>
 *   <li>sub: id do usuário, usado para identificar o dono do token</li>
 *   <li>iat / exp: emissão e expiração</li>
 *   <li>jti: id único do token</li>
 *   <li>roles: perfis, usados na autorização</li>
 *   <li>email / name: dados de exibição, sem informação sensível</li>
 * </ul>
 */
@Service
public class TokenService {

    private final JwtEncoder encoder;
    private final JwtProperties props;
    private final String keyId;

    public TokenService(JwtEncoder encoder, JwtProperties props, RSAKey rsaKey) {
        this.encoder = encoder;
        this.props = props;
        this.keyId = rsaKey.getKeyID();
    }

    public TokenResponse issue(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(props.expiration());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .subject(String.valueOf(user.getId()))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("email", user.getEmail())
                .claim("name", user.getName())
                .claim(SecurityConfig.ROLES_CLAIM, List.of(user.getRole().name()))
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(keyId).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        return new TokenResponse(token, "Bearer", props.expiration().toSeconds(), expiresAt);
    }
}
