package com.example.login.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequest {
    @NotBlank (message = "닉네임을 입력해주세요.")
    @Size(min = 3, max = 20, message = "닉네임은 3 ~ 20글자여야 합니다.")
    private String nickname;

    @NotBlank (message = "이메일을 입력해주세요.")
    @Email(message = "올바른 이메일 형식이여야 합니다.")
    private String email;

    @NotBlank (message = "비밀번호를 입력해주세요.")
    @Size(min = 6, message = "비밀번호는 6자 이상이여야 합니다. ")
    private String password;
}
