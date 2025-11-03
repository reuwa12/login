package com.example.login.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthRequest {

    @NotBlank(message = "이메일을 입력해주세요.")
    private String email;

    @NotBlank(message = "비밀번호를 입력해주세요.")
    private String password;

    @Data
    public static class RefreshToken {
        @NotBlank(message = "리프레시 토큰을 입력해주세요.")
        private String refreshToken;
    }
}
