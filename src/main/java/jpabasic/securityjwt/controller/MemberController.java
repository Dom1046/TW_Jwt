package jpabasic.securityjwt.controller;

import jpabasic.securityjwt.dto.JoinRequestDTO;
import jpabasic.securityjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinRequestDTO joinRequestDTO) {
        memberService.joinProcess(joinRequestDTO);
        return "ok";
    }
}
