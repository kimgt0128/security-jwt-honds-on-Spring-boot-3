package com.security.JWT_Hands_On.jwt.controller;

import com.security.JWT_Hands_On.jwt.dto.ReissueTokenResponse;
import com.security.JWT_Hands_On.jwt.repository.RefreshRepository;
import com.security.JWT_Hands_On.jwt.service.JwtReissueService;
import com.security.JWT_Hands_On.jwt.service.JwtUtil;
import jakarta.servlet.http.Cookie;
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
                                     HttpServletResponse response)
    {
        System.out.println("refreshToken: " + refreshToken);

        ReissueTokenResponse reissueToken = jwtReissueService.reissueToken(refreshToken);


        String newAccessToken = reissueToken.getAccessToken();
        String newRefreshToken = reissueToken.getRefreshToken();

        //response
        //이후 커스텀 예외 처리와 ExceptionHandler로 인한 모듈화 구현
        response.setHeader("access", newAccessToken);
        response.addCookie(createCookie("refresh", newRefreshToken));

        return new ResponseEntity<>(HttpStatus.OK);
    }

    /*
     * 임시 사용을 위한 쿠키 생성 메서드
     * 서비스에 적용시 MemberSignUpService에서 다음 두 메서드를 모듈화
    public static HttpHeaders setCookieAndHeader(LoginResponseDto loginResult) {
    HttpHeaders headers = new HttpHeaders();
    CookieUtil.setRefreshCookie(headers, loginResult.getRefreshToken());
    HttpHeaderUtil.setAccessToken(headers, loginResult.getAccessToken());
    return headers;
  }

  public static HttpHeaders setCookieAndHeader(ReIssueTokenDto reIssueTokenDto) {
    HttpHeaders headers = new HttpHeaders();
    HttpHeaderUtil.setAccessToken(headers, reIssueTokenDto.getAccessToken());
    CookieUtil.setRefreshCookie(headers, reIssueTokenDto.getRefreshToken());
    return headers;
  }

     * ****

     */
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        //cookie.setSecure("true");
        //cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }

}
