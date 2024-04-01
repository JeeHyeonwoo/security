package com.hyeonu.security.controller;

import com.hyeonu.security.dto.request.LoginRequestDto;
import com.hyeonu.security.jwt.TokenInfo;
import com.hyeonu.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController @RequiredArgsConstructor
@RequestMapping("/api")
public class LoginController {
    private final AuthService authService;

    @RequestMapping("/login")
    public ResponseEntity<String> tokenProvider(@RequestBody LoginRequestDto loginRequestDto) {
        log.info("login api");
        String tokenInfo;
        try {
            tokenInfo = authService.login(loginRequestDto);
        } catch(Exception e) {
            log.info(e.getMessage());
            return ResponseEntity.status(HttpStatus.OK).body(null);
        }

        return ResponseEntity.status(HttpStatus.OK).body(tokenInfo);
    }
}
