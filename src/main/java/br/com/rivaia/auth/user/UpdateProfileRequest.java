package br.com.rivaia.auth.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Atualização do próprio perfil. Perfil e status não podem ser alterados aqui. */
public record UpdateProfileRequest(
        @NotBlank @Size(max = 120) String name,
        @NotBlank @Email @Size(max = 160) String email) {
}
