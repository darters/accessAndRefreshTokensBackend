package com.example.accessandrefreshtoken.controller;

import com.example.accessandrefreshtoken.dto.*;
import com.example.accessandrefreshtoken.entity.Role;
import com.example.accessandrefreshtoken.entity.Token;
import com.example.accessandrefreshtoken.entity.User;
import com.example.accessandrefreshtoken.repository.TokenRepository;
import com.example.accessandrefreshtoken.repository.UserRepository;
import com.example.accessandrefreshtoken.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenRepository tokenRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/registration")
    public ResponseEntity<String> registration(@RequestBody RegistrationRequestDTO registrationRequestDTO) {
        try {
            User user = new User();
            if (userRepository.findByUsername(registrationRequestDTO.getUsername()).isPresent()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User with this username already exsits");
            }
            user.setFirstname(registrationRequestDTO.getFirstname());
            user.setUsername(registrationRequestDTO.getUsername());
            user.setPassword(passwordEncoder.encode(registrationRequestDTO.getPassword()));
            user.setRoles(Collections.singleton(Role.USER));
            userRepository.save(user);
            return ResponseEntity.ok("User created successfully");
        } catch (Exception exception) {
            exception.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while creating the user");
        }
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        try {
            Optional<User> userFromDb = userRepository.findByUsername(loginRequestDTO.getUsername());
            if (userFromDb.isPresent()) {
                if (passwordEncoder.matches(loginRequestDTO.getPassword(), userFromDb.get().getPassword())) {
                    String accessToken = jwtService.generateAccessToken(userFromDb.get());
                    String refreshToken = jwtService.generateRefreshToken(userFromDb.get());
                    Optional<Token> tokenFromDb = tokenRepository.findTokenByUserId(userFromDb.get().getId());

                    Token newRefreshToken = new Token();
                    newRefreshToken.setRefreshToken(refreshToken);
                    newRefreshToken.setUser(userFromDb.get());
                    tokenFromDb.ifPresent(token -> newRefreshToken.setId(tokenFromDb.get().getId()));
                    tokenRepository.save(newRefreshToken);

                    TokenResponseDTO tokenDTO = new TokenResponseDTO(accessToken, refreshToken);
                    return ResponseEntity.ok(tokenDTO);
                }
                else return ResponseEntity.badRequest().body("Incorrect password");
            }
            else return ResponseEntity.badRequest().body("User don't exists");
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while login " + exception.getMessage());
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> updateAccessToken(@RequestBody UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) {
        if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid refresh token");
        }
        String username = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            AccessTokenResponse accessTokenResponse = new AccessTokenResponse(jwtService.generateAccessToken(user.get()));
            return ResponseEntity.ok(accessTokenResponse);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User doesn't exist");
    }
}
