package com.hyeonu.security.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hyeonu.security.dto.Users;
import com.hyeonu.security.jwt.JwtProvider;
import com.hyeonu.security.service.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final CustomUserDetailsService customUserDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            String token = authorizationHeader.substring(7);

            // jwt 유효성 검증
            if (jwtProvider.validateToken(token)) {
                try {
                    String username = jwtProvider.parseClaims(token).get("username", String.class);
                    Users users = customUserDetailsService.loadUserByUsername(username);
                    if (users != null) {
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(users, null, users.getAuthorities());
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                        System.out.println("검증완료");
                    }
                }catch (Exception e) {
                    log.info(e.toString());
                }
            }
        }
        System.out.println(SecurityContextHolder.getContext().getAuthentication());

        filterChain.doFilter(request, response);
    }
}
