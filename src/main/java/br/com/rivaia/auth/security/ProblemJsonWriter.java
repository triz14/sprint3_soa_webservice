package br.com.rivaia.auth.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;

import br.com.rivaia.auth.common.error.ApiError;

/**
 * Escreve {@link ApiError} direto na resposta. Usado pelos handlers do
 * Spring Security, que rodam no filtro, antes do @RestControllerAdvice.
 */
final class ProblemJsonWriter {

    private ProblemJsonWriter() {
    }

    static void write(HttpServletResponse response, ApiError error) throws IOException {
        response.setStatus(error.status());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        String json = "{"
                + field("type", error.type()) + ","
                + field("title", error.title()) + ","
                + "\"status\":" + error.status() + ","
                + field("detail", error.detail()) + ","
                + field("instance", error.instance()) + ","
                + field("timestamp", error.timestamp())
                + "}";
        response.getWriter().write(json);
    }

    private static String field(String name, String value) {
        return "\"" + name + "\":\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
