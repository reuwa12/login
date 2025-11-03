package com.example.login.entity;


import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * 애플리케이션에서 회원 정보를 저장하는 JPA 엔티티입니다.
 * <p>
 *  - Spring Security 의 {@link UserDetails} 를 구현하여 인증 시 이메일을 사용자명으로 활용합니다.
 *  - provider 필드로 OAuth 연동과 구분할 수 있도록 설계해두었습니다.
 */
@Entity
@Table(name = "users")
@Data
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 40)
    private String nickname;

    @Column(unique = true, nullable = false)
    private String username;

    //로그인에 사용할 이메일. UNIQUE 제약 조건을 통해 중복 가입을 방지합니다.

    @Column(unique = true, nullable = false, length = 120)
    private String email;

    //Bcrypt 로 인코딩된 비밀번호.

    @JsonIgnore
    @Column(nullable = false)
    private String password;

    /**
     * 소셜 로그인 기본값 LOCAL
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthProvider provider;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 기본 사용자 권한만을 부여합니다. 향후 관리자 권한이 필요하면 이 부분을 확장하면 됩니다.
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        // Spring Security 가 내부적으로 호출하는 사용자명은 이메일을 사용합니다.
        return email;
    }
}