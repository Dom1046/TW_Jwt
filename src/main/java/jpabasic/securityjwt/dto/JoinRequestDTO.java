package jpabasic.securityjwt.dto;

import jakarta.validation.constraints.Pattern;
import jpabasic.securityjwt.entity.embadded.Email;
import jpabasic.securityjwt.entity.embadded.Nickname;
import jpabasic.securityjwt.entity.embadded.Password;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class JoinRequestDTO {
    @Pattern(regexp = "^[a-zA-Z0-9_-]{8,30}$")
    private String userId;
    @Pattern(regexp = Nickname.REGEX, message = Nickname.ERR_MSG)
    private String nickname;
    @Pattern(regexp = Password.REGEX, message = Password.ERR_MSG)
    private String password;
    @Pattern(regexp = Email.REGEX, message = Email.ERR_MSG)
    private String email;
}