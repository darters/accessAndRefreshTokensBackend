package com.example.accessandrefreshtoken.repository;

import com.example.accessandrefreshtoken.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    Optional<Token> findTokenByUserId(Long userId);
}
