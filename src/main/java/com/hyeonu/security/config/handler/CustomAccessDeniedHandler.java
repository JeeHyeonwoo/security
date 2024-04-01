package com.hyeonu.security.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hyeonu.security.dto.response.ResponseResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper;
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.error("NO Authorities: " + accessDeniedException.getMessage());

        Map<String, Object> map = new HashMap<>();
        map.put("error", accessDeniedException.getMessage());
        ResponseResult responseResult = ResponseResult.builder()
                .localDateTime(LocalDateTime.now().toString())
                .Status(HttpStatus.FORBIDDEN.value())
                .message(map)
                .path(request.getRequestURI())
                .build();
        String responseBody = objectMapper.writeValueAsString(responseResult);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setCharacterEncoding("UTF-8");
        response.getWriter().println(responseBody);
    }
}
