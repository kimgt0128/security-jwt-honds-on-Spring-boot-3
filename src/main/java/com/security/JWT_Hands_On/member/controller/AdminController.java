package com.security.JWT_Hands_On.member.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@ResponseBody
@Controller
public class AdminController {


    @GetMapping("/admin")
    public String adminPage() {

        return "admin Contrller";
    }
}
