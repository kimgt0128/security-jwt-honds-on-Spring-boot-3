package com.security.JWT_Hands_On.member.service;

import com.security.JWT_Hands_On.member.dto.CustomUserDetails;
import com.security.JWT_Hands_On.member.entity.MemberJwt;
import com.security.JWT_Hands_On.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //DB에서 특정 유저 조회 후 반한
        MemberJwt memberData = memberRepository.findByMemberName(username);
        if (memberData != null) {
            return new CustomUserDetails(memberData);
        }
        return null;
    }
}
