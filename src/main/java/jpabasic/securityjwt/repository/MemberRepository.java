package jpabasic.securityjwt.repository;

import jpabasic.securityjwt.entity.Member;
import jpabasic.securityjwt.entity.embadded.Email;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Member findByUserId(String userId);
    Boolean existsByUserId(String userId);
    Boolean existsByEmail(Email email);
}
