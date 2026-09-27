package br.com.rivaia.auth.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Atualização completa (PUT) de um usuário pelo ADMIN: dados, perfil e status. */
public record AdminUpdateUserRequest(
        @NotBlank @Size(max = 120) String name,
        @NotBlank @Email @Size(max = 160) String email,
        @NotNull Role role,
        @NotNull Boolean active) {
}
