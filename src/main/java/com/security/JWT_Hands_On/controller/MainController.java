package com.security.JWT_Hands_On.controller;


import lombok.Getter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@ResponseBody
@Controller
public class MainController {

    @GetMapping("/")
    public String mainPage() {
        return "main Controller";
    }

}
