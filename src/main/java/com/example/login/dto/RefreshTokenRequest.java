package com.example.login.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokenRequest {
    @NotBlank(message = "리프레시 토큰이 필요합니다.")
    private String refreshToken;
}