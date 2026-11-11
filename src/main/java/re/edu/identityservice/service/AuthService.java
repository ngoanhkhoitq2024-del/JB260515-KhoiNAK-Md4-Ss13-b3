package re.edu.identityservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import re.edu.identityservice.dto.LoginRequest;
import re.edu.identityservice.dto.RegisterRequest;
import re.edu.identityservice.dto.TokenResponse;
import re.edu.identityservice.dto.UserResponse;
import re.edu.identityservice.entity.User;
import re.edu.identityservice.repository.UserRepository;
import re.edu.identityservice.util.JwtUtil;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    // Xử lý đăng ký tài khoản
    @Transactional
    public UserResponse register(RegisterRequest request) {
        // 1. Kiểm tra dữ liệu đầu vào
        if (request.username() == null ||
                request.username().isBlank() ||
                request.password() == null ||
                request.password().isBlank()) {

            throw new IllegalArgumentException(
                    "Username and password are required"
            );
        }
        // 2. Kiểm tra username đã tồn tại chưa
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException(
                    "Username already exists"
            );
        }
        // 3. Mã hóa password
        String encodedPassword = passwordEncoder.encode(request.password());

        // 4. Tạo User mới
        User user = new User(
                null,
                request.username(),
                encodedPassword,
                "USER"
        );

        // 5. Lưu User vào Database
        User savedUser = userRepository.save(user);

        // 6. Trả dữ liệu an toàn về Client
        return new UserResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getRole()
        );
    }

    public TokenResponse generateTestToken(String username) {
        // 1. Tìm User trong Database
        User user = userRepository.findByUsername(username);

        // 2. Kiểm tra User có tồn tại không
        if (user == null) {
            throw new IllegalArgumentException("User not found");
        }

        // 3. Tạo JWT từ thông tin User
        String token = jwtUtil.generateToken(user);

        // 4. Trả JWT
        return new TokenResponse(token);
    }


    public TokenResponse login(LoginRequest request) {
        // 1. Tìm người dùng theo username
        User user = userRepository.findByUsername(request.username());

        // 2. Kiểm tra tài khoản có tồn tại không
        if (user == null) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Bad credentials"
            );
        }

        // 3. Kiểm tra mật khẩu bằng BCrypt
        boolean passwordMatches = passwordEncoder.matches(
                request.password(),
                user.getPassword()
        );
        if (!passwordMatches) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Bad credentials"
            );
        }
        // 4. Tạo JWT
        String token = jwtUtil.generateToken(user);

        // 5. Trả token về Client
        return new TokenResponse(token);
    }
}
