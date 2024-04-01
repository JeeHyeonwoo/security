package com.hyeonu.security.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @RequestMapping("/")
    public String index(HttpServletRequest request){
        System.out.println("SecurityContextHolder.getContext().getAuthentication() = "
                + SecurityContextHolder.getContext().getAuthentication());
        System.out.println("ss : " + request.getSession().getAttribute("SPRING_SECURITY_CONTEXT"));
        return "index";
    }

    @RequestMapping("/user")
    public String user(HttpServletRequest request) {
        return "user";
    }
}
