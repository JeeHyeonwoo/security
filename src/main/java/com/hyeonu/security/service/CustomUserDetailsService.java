package com.hyeonu.security.service;

import com.hyeonu.security.dto.Users;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service @RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Set<String> authorityList = new HashSet<>();
        authorityList.add("user");

        return Users.builder()
                .username("hyeonu")
                .password(bCryptPasswordEncoder.encode("asd123"))
                .authorityList(authorityList).build();
    }
}
