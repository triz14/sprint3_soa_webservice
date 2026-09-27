package br.com.rivaia.auth.auth;

import java.time.Instant;

/**
 * @param accessToken JWT a ser enviado no header Authorization: Bearer
 * @param tokenType   sempre "Bearer"
 * @param expiresIn   segundos até expirar
 * @param expiresAt   instante exato de expiração (UTC)
 */
public record TokenResponse(String accessToken, String tokenType, long expiresIn, Instant expiresAt) {
}
