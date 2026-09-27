package br.com.rivaia.auth.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.com.rivaia.auth.common.error.AccountDisabledException;
import br.com.rivaia.auth.common.error.InvalidCredentialsException;
import br.com.rivaia.auth.user.Role;
import br.com.rivaia.auth.user.User;
import br.com.rivaia.auth.user.UserRepository;
import br.com.rivaia.auth.user.UserService;

@Service
public class AuthService {

    private static final String INVALID_CREDENTIALS = "E-mail ou senha inválidos.";

    private final UserService userService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    /**
     * Hash usado quando o e-mail não existe, para que a resposta demore o mesmo
     * tempo nos dois casos e não revele quais e-mails estão cadastrados.
     */
    private final String dummyHash;

    public AuthService(UserService userService, UserRepository userRepository,
                       PasswordEncoder passwordEncoder, TokenService tokenService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.dummyHash = passwordEncoder.encode("rivaia-dummy-password");
    }

    public User register(RegisterRequest request) {
        return userService.create(request.name(), request.email(), request.password(), Role.USER);
    }

    @Transactional(readOnly = true)
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(UserService.normalizeEmail(request.email())).orElse(null);
        if (user == null) {
            passwordEncoder.matches(request.password(), dummyHash);
            throw new InvalidCredentialsException(INVALID_CREDENTIALS);
        }
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS);
        }
        if (!user.isActive()) {
            throw new AccountDisabledException("Conta desativada. Procure um administrador.");
        }
        return tokenService.issue(user);
    }
}
