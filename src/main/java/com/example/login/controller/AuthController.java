package com.example.login.controller;

import com.example.login.dto.AuthRequest;
import com.example.login.dto.AuthResponse;
import com.example.login.dto.RefreshTokenRequest;
import com.example.login.dto.SignupRequest;
import com.example.login.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
        // Args: request - 사용자 회원가입 요청 본문.
        // Returns: 발급된 토큰과 함께 HTTP 200 응답을 반환합니다.
        return ResponseEntity.ok(authService.signup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        // Args: request - 로그인 자격 증명(이메일, 비밀번호).
        // Returns: 로그인 성공 시 토큰 정보를 포함한 HTTP 200 응답.
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        // Args: request - 기존에 발급된 리프레시 토큰.
        // Returns: 새 액세스/리프레시 토큰을 담은 HTTP 200 응답.
        return ResponseEntity.ok(authService.refresh(request));
    }
}