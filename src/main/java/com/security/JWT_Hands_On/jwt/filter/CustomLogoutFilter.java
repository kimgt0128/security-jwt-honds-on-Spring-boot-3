package com.security.JWT_Hands_On.jwt.filter;

import com.security.JWT_Hands_On.jwt.repository.RefreshRepository;
import com.security.JWT_Hands_On.jwt.service.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor

public class CustomLogoutFilter extends GenericFilterBean {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    /******************************************************
     * 커스텀 필터 구현
     * 모든 요청은 커스텀 필터를 거쳐 서버로 들어옴
     * [요청 검증 후 다음 필터로 넘김]
     * 요청이 로그아웃인지 확인
     * HTTP 메서드 확인
     *
     * [쿠키에서 Refresh Token 가져오고 검증]
     * 쿠키가 없을 경우 예외 처리
     * Refresh Token이 만료되었다면 예외 처리
     * 토큰이 활성화되어있는 경우 refresh token인지 확인 후 예외 처리
     * DB에서 해당 토큰이 저장되었는지 확인 후 예외 처리
     *
     * [로그아웃 진행]
     * Refresh DB에서 제거
     * Cookie 초기화(시간, 경로, secure 설정 제거)
     * 응답 설정

     ****************************************************************/
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        //요청이 로그아웃인지 확인
        String requestUri = request.getRequestURI();
        System.out.println("요청 uri: " + requestUri);
        if (!requestUri.matches("^/logout$")) {
            filterChain.doFilter(request, response);
            return;
        }

        //HTTP 메서드 확인
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }

        //refresh token 검증
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }
        System.out.println("검증 후 refresh: " + refresh);

        if (refresh == null) {
            System.out.println("refresh is null");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 토큰 만료 검증
        if (jwtUtil.isExpired(refresh)) {
            System.out.println("refresh 토큰이 이미 만료됨");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //토큰 카테고리 검증
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            System.out.println("토큰 카테고리가 refresh가 아님");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // DB에 저장된 토큰인지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            System.out.println("세션 저장소에 해당 refresh 토큰 없음");
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        // 로그아웃 진행

        //Refresh 토큰 DB에서 제거
        refreshRepository.deleteByRefresh(refresh);

        //Refresh 쿠키 값 초기화
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        System.out.println("로그 아웃 성공");
        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }


}
