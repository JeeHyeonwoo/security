package com.hyeonu.security.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hyeonu.security.dto.Users;
import com.hyeonu.security.dto.request.LoginRequestDto;
import com.hyeonu.security.jwt.JwtProvider;
import com.hyeonu.security.jwt.TokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class AuthService {
    private final JwtProvider jwtProvider;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final CustomUserDetailsService customUserDetailsService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String login(LoginRequestDto dto) throws JsonProcessingException {
        Users users = customUserDetailsService.loadUserByUsername(dto.getUsername());

        if(users == null) {
            throw new UsernameNotFoundException("존재하지 않는 아이디입니다");
        }
        if(!bCryptPasswordEncoder.matches(dto.getPassword(), users.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다");
        }

        return objectMapper.writeValueAsString(jwtProvider.generateToken(users));
    }
}
