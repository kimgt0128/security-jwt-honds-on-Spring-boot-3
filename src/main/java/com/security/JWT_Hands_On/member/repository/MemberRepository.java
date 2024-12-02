package com.security.JWT_Hands_On.member.repository;

import com.security.JWT_Hands_On.member.entity.MemberJwt;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<MemberJwt, Long> {
    Boolean existsByMemberName(String name);

    MemberJwt findByMemberName(String username);
}
