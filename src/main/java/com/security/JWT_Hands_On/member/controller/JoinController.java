package com.security.JWT_Hands_On.member.controller;


import com.security.JWT_Hands_On.member.dto.JoinRequsetDto;
import com.security.JWT_Hands_On.member.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@ResponseBody
@RequiredArgsConstructor

@Controller
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinRequsetDto request) {
        joinService.joinProcess(request);
        return "OK";
    }


}
