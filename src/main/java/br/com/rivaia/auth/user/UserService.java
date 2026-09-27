package br.com.rivaia.auth.user;

import java.util.Locale;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.com.rivaia.auth.common.error.AccountDisabledException;
import br.com.rivaia.auth.common.error.BusinessRuleException;
import br.com.rivaia.auth.common.error.ConflictException;
import br.com.rivaia.auth.common.error.ResourceNotFoundException;

@Service
public class UserService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        return repository.existsByEmail(normalizeEmail(email));
    }

    @Transactional
    public User create(String name, String email, String rawPassword, Role role) {
        String normalized = normalizeEmail(email);
        if (repository.existsByEmail(normalized)) {
            throw new ConflictException("Já existe um usuário cadastrado com este e-mail.");
        }
        User user = new User(name.trim(), normalized, passwordEncoder.encode(rawPassword), role);
        return repository.save(user);
    }

    @Transactional(readOnly = true)
    public User findById(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Usuário " + id + " não encontrado."));
    }

    /**
     * Busca o dono do token. Se a conta foi desativada depois da emissão do
     * token, o acesso é negado mesmo com o JWT ainda dentro da validade.
     */
    @Transactional(readOnly = true)
    public User findActiveById(Long id) {
        User user = findById(id);
        if (!user.isActive()) {
            throw new AccountDisabledException("Conta desativada.");
        }
        return user;
    }

    @Transactional(readOnly = true)
    public Page<User> list(int page, int size) {
        return repository.findAll(PageRequest.of(page, size, Sort.by("id")));
    }

    @Transactional
    public User updateProfile(Long userId, UpdateProfileRequest request) {
        User user = findActiveById(userId);
        applyNameAndEmail(user, request.name(), request.email());
        return user;
    }

    @Transactional
    public void changePassword(Long userId, ChangePasswordRequest request) {
        User user = findActiveById(userId);
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new BusinessRuleException("A senha atual está incorreta.");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
    }

    @Transactional
    public User adminUpdate(Long actorId, Long targetId, AdminUpdateUserRequest request) {
        User user = findById(targetId);
        boolean removesOwnAdminAccess = actorId.equals(targetId)
                && (request.role() != Role.ADMIN || !request.active());
        if (removesOwnAdminAccess) {
            throw new ConflictException("O administrador não pode remover o próprio perfil ADMIN nem se desativar.");
        }
        applyNameAndEmail(user, request.name(), request.email());
        user.setRole(request.role());
        user.setActive(request.active());
        return user;
    }

    @Transactional
    public void delete(Long actorId, Long targetId) {
        if (actorId.equals(targetId)) {
            throw new ConflictException("O administrador não pode excluir a própria conta.");
        }
        User user = findById(targetId);
        repository.delete(user);
    }

    private void applyNameAndEmail(User user, String name, String email) {
        String normalized = normalizeEmail(email);
        if (repository.existsByEmailAndIdNot(normalized, user.getId())) {
            throw new ConflictException("Já existe um usuário cadastrado com este e-mail.");
        }
        user.setName(name.trim());
        user.setEmail(normalized);
    }
}
