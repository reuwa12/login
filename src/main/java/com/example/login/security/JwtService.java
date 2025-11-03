package com.example.login.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshTokenExpiration;

    // ------------------- 토큰 생성 -------------------
    // 회원가입/로그인 access token 생성
    public String generateToken(UserDetails userDetails) {
        // jwt 추가로 담을 정보
        Map<String, Object> extraClaims = new HashMap<>();

        //UserDetails가 실제 User 엔티티 타입일 경우, 추가 정보 추출
        if (userDetails instanceof User user) {
            extraClaims.put("id", user.getId());
            extraClaims.put("email", user.getEmail());
            extraClaims.put("nickname", user.getNickname());
        }

        return generateToken(extraClaims, userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    // RefreshToken 발급
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            Long expiration
    ) {
        return Jwts.builder()
                .setClaims(extraClaims) // 클라이언트/추가 정보용
                .setSubject(userDetails.getUsername()) // sub = email
                .setIssuedAt(new Date(System.currentTimeMillis())) //토큰 발급시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) //토큰 만료 시간 설정
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ------------------- 토큰 검증 -------------------
    // 사용자 식별값과 DB 비교
    public boolean isTokenValid(String token, UserDetails userDetails) {
        // 식별값 추출
        final String identifier = extractUser(token);

        if (userDetails instanceof User user) {
            // user에 저장된 이메일과 token에 저장된 이메일 비교
            boolean isValid = identifier.equals(user.getEmail());

            // 식별값 일치 && 토큰 활성상태
            return isValid && isTokenActive(token);
        }
        return (identifier.equals(userDetails.getUsername()) && isTokenActive(token));
    }

    // 토큰 활성 체크
    public boolean isTokenActive(String token) {
        return extractTokenExpiration(token).after(new Date());    // 만료시간 > 현재시간 = true
    }

    // ---------------- 토큰 정보 추출 -------------------
    // Claims 전체 추출
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 특정 Claims 추출
    public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getClaims(token);
        return claimsResolver.apply(claims);
    }

    // 사용자 식별값 추출 ( ex: id, email)
    public String extractUser(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    // 만료 시간 추출
    private Date extractTokenExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    // 생성/검증 용
    private Key getSignInKey() {
        byte[] keybytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keybytes);
    }
}