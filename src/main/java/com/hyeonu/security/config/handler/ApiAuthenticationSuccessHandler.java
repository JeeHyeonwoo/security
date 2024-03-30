package com.hyeonu.security.config.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class ApiAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
//    JwtTokenProvider jwtTokenProvider = new JwtTokenProvider("VlwEyVBsYt9V7zq57TejMnVUyzblYcfPQye08f7MGVA9XkHa");

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("로그인 성공");

//        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        response.getWriter().println("로그인 성공");
    }
}
