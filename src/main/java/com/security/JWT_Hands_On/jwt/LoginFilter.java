package com.security.JWT_Hands_On.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

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
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) {


    }

}
