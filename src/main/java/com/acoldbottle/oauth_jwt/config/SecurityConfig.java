package com.acoldbottle.oauth_jwt.config;

import com.acoldbottle.oauth_jwt.config.oauth.CustomOAuth2UserService;
import com.acoldbottle.oauth_jwt.jwt.CustomSuccessHandler;
import com.acoldbottle.oauth_jwt.jwt.JWTFilter;
import com.acoldbottle.oauth_jwt.jwt.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    public SecurityConfig(CustomOAuth2UserService oAuth2UserService, CustomSuccessHandler successHandler, JWTUtil jwtUtil) {
        this.oAuth2UserService = oAuth2UserService;
        this.customSuccessHandler = successHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }))
                .csrf(AbstractHttpConfigurer::disable)    // JWT 발급해서 STATELESS 상태로 세션 관리하기 때문 --> disable
                .formLogin(AbstractHttpConfigurer::disable) // OAuth2 와 JWT 방식을 사용할거기 때문에 --> disable
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .oauth2Login((auth) -> auth
                        .userInfoEndpoint((userInfoEndpointConfig -> userInfoEndpointConfig
                                .userService(oAuth2UserService)))
                        .successHandler(customSuccessHandler))
                .authorizeHttpRequests((auth) -> auth   // 경로별 인가 작업
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated())
                .sessionManagement((session) -> session // 세션 설정 : STATELESS
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));



        return http.build();
    }
}
