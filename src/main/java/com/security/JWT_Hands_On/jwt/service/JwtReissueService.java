package com.security.JWT_Hands_On.jwt.service;


import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor

@Service
public class JwtReissueService {

    private final JwtUtil jwtUtil;

    public String reissueToken(String refreshToken) {


        System.out.println("session: " + jwtUtil.getUsername(refreshToken));
        System.out.println("category: " + jwtUtil.getCategory(refreshToken));

        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Refresh token null");
        }
        if (jwtUtil.isExpired(refreshToken)) {
            throw new IllegalArgumentException("Refresh token expired");
        }

        String category = jwtUtil.getCategory(refreshToken);
        if(!category.equals("refresh")) {
            throw new IllegalArgumentException("Token category is not refresh");
        }

        //refresh token으로부터 username, role 가져오기
        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        //새로운 jwt token 만들기
        System.out.println("reissued token created");
        return jwtUtil.createJwt("access", username, role, 600000L);

    }
}
