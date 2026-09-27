package br.com.rivaia.auth.common.error;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Formato único de erro da API, inspirado na RFC 9457 (Problem Details).
 * Toda resposta de erro (validação, regra de negócio, 401, 403, 404, 409, 500)
 * sai neste formato, com Content-Type application/problem+json.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        String type,
        String title,
        int status,
        String detail,
        String instance,
        String timestamp,
        List<FieldViolation> errors) {

    public static ApiError of(int status, String title, String detail, String instance) {
        return new ApiError("about:blank", title, status, detail, instance, Instant.now().toString(), null);
    }

    public static ApiError withErrors(int status, String title, String detail, String instance,
                                      List<FieldViolation> errors) {
        return new ApiError("about:blank", title, status, detail, instance, Instant.now().toString(), errors);
    }

    public record FieldViolation(String field, String message) {
    }
}
