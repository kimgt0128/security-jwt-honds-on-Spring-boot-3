package com.security.JWT_Hands_On.jwt.service;


import com.security.JWT_Hands_On.jwt.dto.ReissueTokenResponse;
import com.security.JWT_Hands_On.jwt.entity.RefreshEntity;
import com.security.JWT_Hands_On.jwt.repository.RefreshRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;

@RequiredArgsConstructor

@Service
public class JwtReissueService {

    private final JwtUtil jwtUtil;
    private  final RefreshRepository refreshRepository;

    public ReissueTokenResponse reissueToken(String refreshToken) {


        System.out.println("session: " + jwtUtil.getUsername(refreshToken));
        System.out.println("category: " + jwtUtil.getCategory(refreshToken));

        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Refresh token null");
        }
        if (jwtUtil.isExpired(refreshToken)) {
            throw new IllegalArgumentException("Refresh token expired");
        }

        String category = jwtUtil.getCategory(refreshToken);
        System.out.println("category: " + category);
        if(!category.equals("refresh")) {
            throw new IllegalArgumentException("Token category is not refresh");
        }

        //DB에 refresh token이 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refreshToken);
        if(!isExist) {
            throw new IllegalArgumentException("Refresh token does not exist, Invalid access token");
        }

        //refresh token으로부터 username, role 가져오기
        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        //새로운 jwt token 만들기
        //refresh rotate를 사용하도록 반환
        System.out.println("reissued token created");
        String newAccessToken = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefreshToken = jwtUtil.createJwt("refresh", username, role, 86400000L);

        //기존의 refresh 토큰 삭제 후 새 refresh 토큰 저장
        refreshRepository.deleteByRefresh(refreshToken);
        addRefreshEntity(username, newRefreshToken, 86400000L);

        return new ReissueTokenResponse(newRefreshToken, newAccessToken);
    }

    private void addRefreshEntity(String username, String refresh, Long expireMs) {
        //세션 만료 일자 생성
        Date date = new Date(System.currentTimeMillis() + expireMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }
}
