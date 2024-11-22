package com.security.JWT_Hands_On.jwt;


import com.security.JWT_Hands_On.dto.CustomUserDetails;
import com.security.JWT_Hands_On.entity.MemberJwt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.lang.reflect.Member;

@RequiredArgsConstructor

public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    /**********************
    * Filter에 대한 내부 구현
    * 요청으로부터 JWT를 추출
    * JWT 검증 필터 구현
    **********************/

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request로부터 Authorization 헤더를 찾음
        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("authorizationHeader: " + authorizationHeader);

        //Authorization 헤더 검증
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            //현재 필터를 종료하고 request와 response를 다음 필터로 전달
            filterChain.doFilter(request, response);
            return;
        }


        //Barer 부분 제거 후 순수 토큰만 획득
        String token = authorizationHeader.split(" ")[1];
        System.out.println("token: " + token);

        //남은 세션 시간 정보 출력

        //토큰 소멸 시간 검증
        System.out.println("isExpired: " + jwtUtil.isExpired(token));
        if (jwtUtil.isExpired(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //엔티티를 생성하여 값 설정
        MemberJwt memberEntity = new MemberJwt();
        memberEntity.setMemberName(username);
        memberEntity.setMemberPassword("temppassword"); //임시 비밀 번호 생성: 매번 요청시마다 DB에서 조회하므로 비효율
        memberEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(memberEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
