package com.security.JWT_Hands_On.jwt.controller;

import com.security.JWT_Hands_On.jwt.service.JwtReissueService;
import com.security.JWT_Hands_On.jwt.service.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor

@RestController
public class ReissuController {

    private final JwtUtil jwtUtil;
    private final JwtReissueService jwtReissueService;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@CookieValue(name = "refresh") String refreshToken,
                                     HttpServletRequest request,
                                     HttpServletResponse response) {
        System.out.println("refreshToken: " + refreshToken);

        String newAccess = jwtReissueService.reissueToken(refreshToken);
        response.setHeader("access", newAccess);
        return new ResponseEntity<>(HttpStatus.OK);


    }
}
