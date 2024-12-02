package com.security.JWT_Hands_On.config;

import com.security.JWT_Hands_On.jwt.filter.CustomLogoutFilter;
import com.security.JWT_Hands_On.jwt.filter.JWTFilter;
import com.security.JWT_Hands_On.jwt.repository.RefreshRepository;
import com.security.JWT_Hands_On.jwt.service.JwtUtil;
import com.security.JWT_Hands_On.jwt.filter.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@RequiredArgsConstructor

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration  configuration) throws Exception {
        return configuration.getAuthenticationManager();
    };

    //비밀번호 암호화 메서드
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration config = new CorsConfiguration();

                                config.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                                config.setAllowedMethods(Collections.singletonList("*"));
                                config.setAllowCredentials(true);
                                config.setAllowedHeaders(Collections.singletonList("*"));
                                config.setMaxAge(3600L);

                                config.setExposedHeaders(Collections.singletonList("Authorization"));

                                return config;
                            }
                        }))
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/" , "/join", "/reissue").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                //JWT를 통한 인증/인가를 위해 세션을 STATELESS로 설정
                .sessionManagement((session) -> session
                        .sessionCreationPolicy((SessionCreationPolicy.STATELESS))
                )
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class)
                /*
                로그인 필터 추가
                필터가 중복 호출될 수 있으므로 Bean을 이용한 종속성 주입 대신 객체 생성 후 의존성 주입
                 */
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshRepository), UsernamePasswordAuthenticationFilter.class)
                //로그아웃 필터 등록
                .addFilterAt(new CustomLogoutFilter(jwtUtil, refreshRepository), LogoutFilter.class);

        return http.build();
    }
}
