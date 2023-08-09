package com.spring.jpa.postgresql.controller;

import com.spring.jpa.postgresql.exception.TokenRefreshException;
import com.spring.jpa.postgresql.model.RefreshToken;
import com.spring.jpa.postgresql.payload.response.MessageResponse;
import com.spring.jpa.postgresql.repository.RefreshTokenRepository;
import com.spring.jpa.postgresql.security.jwt.JwtUtils;
import com.spring.jpa.postgresql.security.services.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import com.spring.jpa.postgresql.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
public class ProfileController {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    JwtUtils jwtUtils;

    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'MODERATOR', 'ADMIN', 'TEACHER')")
    public ResponseEntity<?> profileAccess(@RequestParam String login, HttpServletRequest request){
        String accessToken = jwtUtils.getJwtFromCookies(request);
        String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);
        try {
            boolean refreshIsValid = jwtUtils.validateRefreshTokenByLogin(refreshToken, login);
            boolean accessIsValid = jwtUtils.validateAccessTokenByLogin(accessToken, login);
            if (refreshIsValid && accessIsValid){
                UserDetails userInfo = userDetailsService.loadUserByUsername(login);
                return ResponseEntity.ok().body(userInfo);
            }
            return ResponseEntity.badRequest().body(new MessageResponse("Requested login is incorrect!"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

}
