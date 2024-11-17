package jpabasic.securityjwt.service;

import jpabasic.securityjwt.dto.JoinRequestDTO;
import jpabasic.securityjwt.entity.Member;
import jpabasic.securityjwt.entity.MemberRole;
import jpabasic.securityjwt.entity.embadded.Email;
import jpabasic.securityjwt.entity.embadded.Nickname;
import jpabasic.securityjwt.entity.embadded.Password;
import jpabasic.securityjwt.exception.MemberException;
import jpabasic.securityjwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder encoder;

    public void joinProcess(JoinRequestDTO joinRequestDTO) {

        Boolean isExistId = memberRepository.existsByUserId(joinRequestDTO.getUserId());
        Boolean isExistEmail = memberRepository.existsByEmail(new Email(joinRequestDTO.getEmail()));

        if (isExistId) {
            throw MemberException.DUPLICATE_USERID.get();
        }
        if (isExistEmail) {
            throw MemberException.DUPLICATE_EMAIL.get();
        }
        Member data = Member.builder()
                .userId(joinRequestDTO.getUserId())
                .nickname(new Nickname(joinRequestDTO.getNickname()))
                .password(new Password(joinRequestDTO.getPassword(),encoder))
                .email(new Email(joinRequestDTO.getEmail()))
                .role(MemberRole.ROLE_USER)
                .build();

        memberRepository.save(data);
    }
}
