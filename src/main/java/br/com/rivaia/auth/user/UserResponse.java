package br.com.rivaia.auth.user;

import java.time.Instant;

/** Representação pública do usuário. Nunca expõe o hash da senha. */
public record UserResponse(
        Long id,
        String name,
        String email,
        Role role,
        boolean active,
        Instant createdAt,
        Instant updatedAt) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getName(), user.getEmail(), user.getRole(),
                user.isActive(), user.getCreatedAt(), user.getUpdatedAt());
    }
}
