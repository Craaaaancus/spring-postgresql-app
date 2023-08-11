package com.spring.jpa.postgresql.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Objects;

import com.spring.jpa.postgresql.exception.TokenRefreshException;
import com.spring.jpa.postgresql.model.RefreshToken;
import com.spring.jpa.postgresql.model.User;
import com.spring.jpa.postgresql.security.services.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.spring.jpa.postgresql.security.services.UserDetailsImpl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.util.WebUtils;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Autowired
    RefreshTokenService refreshTokenService;

    @Value("${app.jwtCookieName}")
    private String jwtCookie;

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${app.jwtRefreshCookieName}")
    private String jwtRefreshCookie;

    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal.getUsername());
        return generateCookie(jwtCookie, jwt, "/");
    }

    public ResponseCookie generateJwtCookie(User user) {
        String jwt = generateTokenFromUsername(user.getUsername());
        return generateCookie(jwtCookie, jwt, "/");
    }

    public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
        return generateCookie(jwtRefreshCookie, refreshToken, "/");
    }

    public String getJwtFromCookies(HttpServletRequest request) {
        return getCookieValueByName(request, jwtCookie);
    }

    public String getJwtRefreshFromCookies(HttpServletRequest request) {
        return getCookieValueByName(request, jwtRefreshCookie);
    }

    public ResponseCookie getCleanJwtCookie() {
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/").build();
        return cookie;
    }

    public ResponseCookie getCleanJwtRefreshCookie() {
        ResponseCookie cookie = ResponseCookie.from(jwtRefreshCookie, null).path("/").build();
        return cookie;
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public boolean validateAccessTokenByLogin(String accessToken, String login) {
        if (accessToken == null || !validateJwtToken(accessToken)) return false;
        String tokenLogin = getUserNameFromJwtToken(accessToken);
        return Objects.equals(tokenLogin, login);
    }

    public boolean validateRefreshTokenByLogin(String refreshToken, String login) throws TokenRefreshException {
        if (refreshToken == null || refreshToken.length() == 0) return false;

        return refreshTokenService.findByToken(refreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> Objects.equals(user.getUsername(), login))
                .orElseThrow(() -> new TokenRefreshException(
                        refreshToken, "Refresh token is not in database!"
                ));
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    private ResponseCookie generateCookie(String name, String value, String path) {
        if (Objects.equals(name, jwtCookie)){
            return ResponseCookie
                    .from(name, value)
                    .path(path)
                    .httpOnly(true)
                    .build();
        }
        return ResponseCookie
                .from(name, value)
                .path(path)
                .maxAge(24 * 60 * 60)
                .httpOnly(true)
                .build();
    }

    private String getCookieValueByName(HttpServletRequest request, String name) {
        Cookie cookie = WebUtils.getCookie(request, name);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }
}
