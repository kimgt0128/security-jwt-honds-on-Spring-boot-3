package com.security.JWT_Hands_On.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class ReissueTokenResponse {

    private final String refreshToken;
    private final String accessToken;
}
