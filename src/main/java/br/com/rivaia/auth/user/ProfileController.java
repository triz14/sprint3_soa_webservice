package br.com.rivaia.auth.user;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.rivaia.auth.config.OpenApiConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Perfil do usuário autenticado. O usuário é identificado pelo claim "sub"
 * do token, nunca por um id vindo da URL, então ninguém altera dados de outro.
 */
@RestController
@RequestMapping("/api/v1/users/me")
@Tag(name = "Meu perfil", description = "Operações do usuário autenticado (USER ou ADMIN)")
@SecurityRequirement(name = OpenApiConfig.BEARER)
@ApiResponse(responseCode = "401", description = "Token ausente, inválido ou expirado")
public class ProfileController {

    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "Dados do usuário dono do token")
    @ApiResponse(responseCode = "200", description = "Perfil retornado")
    @ApiResponse(responseCode = "403", description = "Conta desativada")
    @GetMapping
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return UserResponse.from(userService.findActiveById(userId(jwt)));
    }

    @Operation(summary = "Atualiza nome e e-mail do próprio perfil")
    @ApiResponse(responseCode = "200", description = "Perfil atualizado")
    @ApiResponse(responseCode = "400", description = "Dados inválidos")
    @ApiResponse(responseCode = "409", description = "E-mail já usado por outro usuário")
    @PutMapping
    public UserResponse update(@AuthenticationPrincipal Jwt jwt,
                               @Valid @RequestBody UpdateProfileRequest request) {
        return UserResponse.from(userService.updateProfile(userId(jwt), request));
    }

    @Operation(summary = "Troca a própria senha")
    @ApiResponse(responseCode = "204", description = "Senha alterada")
    @ApiResponse(responseCode = "400", description = "Senha atual incorreta ou nova senha inválida")
    @PutMapping("/password")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal Jwt jwt,
                                               @Valid @RequestBody ChangePasswordRequest request) {
        userService.changePassword(userId(jwt), request);
        return ResponseEntity.noContent().build();
    }

    static Long userId(Jwt jwt) {
        return Long.valueOf(jwt.getSubject());
    }
}
