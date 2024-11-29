package com.security.JWT_Hands_On.member.service;

import com.security.JWT_Hands_On.member.dto.JoinRequsetDto;
import com.security.JWT_Hands_On.member.entity.MemberJwt;
import com.security.JWT_Hands_On.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor

@Service
public class JoinService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinRequsetDto request) {

        String memberName = request.getMemberName();
        String password = request.getPassword();

        //memberName 중복 검사
        if (memberRepository.existsByMemberName(memberName)) {
            System.out.println("이미 존재하는 회원입니다.");
            return;
        }

        //회원 가입 진행
        MemberJwt member = new MemberJwt();
        member.setMemberName(memberName);
        member.setMemberPassword(bCryptPasswordEncoder.encode(password));
        member.setRole("ROLE_ADMIN");
        memberRepository.save(member);
    }
}
