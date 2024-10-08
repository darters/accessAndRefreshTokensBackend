package com.example.accessandrefreshtoken.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestDTO {
    private String username;
    private String password;

    public LoginRequestDTO(String username) {
        this.username = username;
    }
}
