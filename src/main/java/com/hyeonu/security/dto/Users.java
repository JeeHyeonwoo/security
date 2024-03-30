package com.hyeonu.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Builder
@AllArgsConstructor
public class Users implements UserDetails {
    @Setter private String username;
    @Setter private String password;
    private Set<String> authorityList;

    public void addAuthority(String authority) {
        this.authorityList.add(authority);
    }

    public boolean removeAuthority(String authority){
        return authorityList.remove(authority);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorityList.stream().map((authority)-> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
