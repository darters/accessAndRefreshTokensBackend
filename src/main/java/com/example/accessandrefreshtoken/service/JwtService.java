package com.example.accessandrefreshtoken.service;

import com.example.accessandrefreshtoken.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtService {
    private String accessSecret = "fdkjlsjfkldsjfkldafhliehdjkshgajkjkfincvxkjuvzimfjnvxivoinerji432jkisdfvcxio4";
    private String refreshSecret = "fajsdfkljslnzufhugeqyewqwiopeoiqueyuyzIOyz786e786wrtwfgyiyzyuiyzuiunewrwrsxg";
    @Value("${jwt.expiration.access}")
    private Long accessExpirationTimeInMs;
    @Value("${jwt.expiration.refresh}")
    private Long refreshExpirationTimeInMs;

    public String generateAccessToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("firstname", user.getFirstname())
                .claim("role", user.getRoles())
                .signWith(getSignSecretKey(accessSecret))
                .expiration(new Date(System.currentTimeMillis() + accessExpirationTimeInMs))
                .compact();
    }
    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .signWith(getSignSecretKey(refreshSecret))
                .expiration(new Date(System.currentTimeMillis() + refreshExpirationTimeInMs))
                .compact();
    }
    private SecretKey getSignSecretKey(String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean validateToken(String token, String secret) {
        try {
            Jwts.parser()
                    .verifyWith(getSignSecretKey(secret))
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException exception) {
            System.out.println("Token is expired: " + exception);
        } catch (UnsupportedJwtException unsEx) {
            System.out.println("Unsupported jwt" + unsEx);
        } catch (MalformedJwtException mjEx) {
            System.out.println("Malformed jwt" + mjEx);
        } catch (Exception e) {
            System.out.println("invalid token" + e);
        }
        return false;
    }
    public Claims getAccessTokenClaims(String token) {
        return getClaims(token, accessSecret);
    }
    public Claims getRefreshTokenClaims(String token) {
        return getClaims(token, refreshSecret);
    }
    public boolean validateRefreshToken(String token) {
        return validateToken(token, refreshSecret);
    }
    public boolean validateAccessToken(String token) {
        return validateToken(token, accessSecret);
    }
    public String extractUsernameAccessToken(String token) {
        Claims claims = getClaims(token, accessSecret);
        return claims.getSubject();
    }
    public Claims getClaims(@NonNull String token, @NonNull String secretKey) {
        return Jwts.parser()
                .verifyWith(getSignSecretKey(secretKey))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
