package com.example.learning.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;


@ConfigurationProperties(prefix = "application.jwt")
@Data
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;

    public String getAuthorizationHeader() {
        return AUTHORIZATION;
    }
}
