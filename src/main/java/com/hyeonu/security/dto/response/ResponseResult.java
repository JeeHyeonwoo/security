package com.hyeonu.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import java.util.Map;

@Data @AllArgsConstructor @Builder
public class ResponseResult {
    private String localDateTime;
    private int Status;
    private Map<String, Object> message;
    private String path;
}
