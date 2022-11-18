package com.microservices.server.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig extends WebSecurityConfigurerAdapter {

    private final String[] swaggerPaths;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        var httpSecurity = http.authorizeRequests();
        handleSwaggerPaths(httpSecurity);
        httpSecurity
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
                .and()
                .oauth2ResourceServer()
                .jwt();
    }

    private void handleSwaggerPaths(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry http) {
        if (ArrayUtils.isEmpty(swaggerPaths)) {
            return;
        }
        http.antMatchers(swaggerPaths).permitAll();
    }

}
