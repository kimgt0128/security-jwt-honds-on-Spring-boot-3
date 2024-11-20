package com.security.JWT_Hands_On.repository;

import com.security.JWT_Hands_On.entity.MemberJwt;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<MemberJwt, Long> {
}
