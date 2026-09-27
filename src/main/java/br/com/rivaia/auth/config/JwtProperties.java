package br.com.rivaia.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configurações do token JWT emitido por este serviço.
 *
 * @param issuer     valor do claim "iss"; os serviços consumidores validam esse valor
 * @param expiration tempo de vida do access token (ex.: 1h, 15m)
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String issuer, Duration expiration) {
}
