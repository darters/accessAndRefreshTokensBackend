package com.example.accessandrefreshtoken.entity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {
    ADMIN("ADMIN"),
    USER("USER");

    private final String role;
    @Override
    public String getAuthority() {
        return role;
    }
}
