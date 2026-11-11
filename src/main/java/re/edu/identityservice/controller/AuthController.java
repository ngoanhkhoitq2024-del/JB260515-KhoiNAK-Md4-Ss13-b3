
package re.edu.identityservice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import re.edu.identityservice.dto.LoginRequest;
import re.edu.identityservice.dto.RegisterRequest;
import re.edu.identityservice.dto.TokenResponse;
import re.edu.identityservice.dto.UserResponse;
import re.edu.identityservice.service.AuthService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @RequestBody RegisterRequest request) {
        UserResponse response = authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @GetMapping("/test-token")
    public ResponseEntity<TokenResponse> testToken(
            @RequestParam String username) {
        System.out.println(">>> DA VAO LOGIN CONTROLLER");
        TokenResponse response = authService.generateTestToken(username);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest request) {
        TokenResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }
}
