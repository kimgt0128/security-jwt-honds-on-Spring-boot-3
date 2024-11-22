package com.security.JWT_Hands_On.jwt;

import com.security.JWT_Hands_On.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //클라이언트 요청에서 username, password 추출
        String memberName = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username: " + memberName);

        //memberName과 password를 검증하기 위해 Authentication Manager에게 전달할 DTO 토큰 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(memberName, password, null);

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterchain, Authentication authentication) {
        //시큐리티에서 제공하는 CustomUserDetail 객체 생성
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        //username 설정
        String username = customUserDetails.getUsername();

        //authentication으로부터 Role값 가져오기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        System.out.println("login success");
        System.out.println("username: " + username);
        System.out.println("role: " + role);


        String token = jwtUtil.createJwt(username, role, 66 * 60 * 1000L);

        //RFC 7235 정의에 따른 HTTP 인증 방식 설정
        response.addHeader("Authorization", "Bearer " + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        System.out.println("login fail");
        response.setStatus(401);
    }
}
