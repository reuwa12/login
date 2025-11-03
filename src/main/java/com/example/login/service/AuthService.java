package com.example.login.service;

import com.example.login.dto.AuthRequest;
import com.example.login.dto.AuthResponse;
import com.example.login.dto.RefreshTokenRequest;
import com.example.login.dto.SignupRequest;
import com.example.login.entity.AuthProvider;
import com.example.login.entity.User;
import com.example.login.repository.UserRepository;
import com.example.login.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    //회원가입 기능

    public AuthResponse signup(SignupRequest signupRequest) {
        // 이메일 중복 체크
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        // 닉네임 중복 체크
        if (userRepository.existsByNickname(signupRequest.getNickname())) {
            throw new IllegalArgumentException("Nickname already exists");
        }

        // 새 사용자 생성
        User user = User.builder()
                .nickname(signupRequest.getNickname())
                .username(signupRequest.getEmail()) // 스프링 시큐리티의 username 필드
                .email(signupRequest.getEmail())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .provider(AuthProvider.LOCAL)
                .build();

        // DB 저장
        User savedUser = userRepository.save(user);

        // JWT 토큰 발급
        String accessToken = jwtService.generateToken(savedUser);
        String refreshToken = jwtService.generateRefreshToken(savedUser);

        // 발급한 리프레시 토큰을 엔티티에 저장해 다음 요청에서 검증할 수 있도록 합니다.
        savedUser.setRefreshToken(refreshToken);
        userRepository.save(savedUser);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // 로그인 기능
    public AuthResponse login(AuthRequest authRequest) {
        try {
            // AuthenticationManager를 사용하여 로그인 인증 수행
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getEmail(),
                            authRequest.getPassword()
                    )
            );

            // 인증된 사용자 정보 가져오기
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Access, Refresh 토큰 발급
            String accessToken = jwtService.generateToken(userDetails);
            String refreshToken = jwtService.generateRefreshToken(userDetails);

            // 인증된 사용자의 엔티티를 조회하여 새 리프레시 토큰을 저장합니다.
            User user = userRepository.findByEmail(userDetails.getUsername())
                    .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
            user.setRefreshToken(refreshToken);
            userRepository.save(user);

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();

        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid email or password", e);
        }
    }

    //리프레시 토큰으로 Access Token 재발급

    public AuthResponse refresh(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        String email = jwtService.extractUser(refreshToken);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if (!jwtService.isTokenValid(refreshToken, user)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        // 데이터베이스에 저장된 리프레시 토큰과 일치하는지도 확인합니다.
        if (user.getRefreshToken() == null || !user.getRefreshToken().equals(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        // 새 토큰 발급
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // 재발급된 리프레시 토큰을 저장하여 이전 토큰을 무효화합니다.
        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }
}