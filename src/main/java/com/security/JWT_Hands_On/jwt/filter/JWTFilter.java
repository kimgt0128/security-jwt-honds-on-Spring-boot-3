package com.security.JWT_Hands_On.jwt.filter;


import com.security.JWT_Hands_On.member.dto.CustomUserDetails;
import com.security.JWT_Hands_On.member.entity.MemberJwt;
import com.security.JWT_Hands_On.jwt.service.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor

public class JWTFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    /**********************
    * Filter에 대한 내부 구현
    * 요청으로부터 JWT를 추출
    * JWT 검증 필터 구현
    **********************/

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = request.getHeader("access");

        //토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        //토큰 만료 여부 확인(만료시 다음 필터로 넘기지 않고 응답 생성)
        try{
            jwtUtil.isExpired(accessToken);
        }
        catch (ExpiredJwtException e){

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("acccess token expired");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        //토큰이 access인지 확인(발급시 페이로드 명시)
        String cagegory = jwtUtil.getCategory(accessToken);
        if (!cagegory.equals("access")) {
            PrintWriter writer = response.getWriter();

            //response status code
            writer.print("invalid access token");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }



        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        //엔티티를 생성하여 값 설정
        MemberJwt memberEntity = new MemberJwt();
        memberEntity.setMemberName(username);
        //memberEntity.setMemberPassword("temppassword"); //임시 비밀 번호 생성: 매번 요청시마다 DB에서 조회하므로 비효율
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
