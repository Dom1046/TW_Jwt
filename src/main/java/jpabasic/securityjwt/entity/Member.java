package jpabasic.securityjwt.entity;

import jakarta.persistence.*;
import jpabasic.securityjwt.entity.embadded.Email;
import jpabasic.securityjwt.entity.embadded.Nickname;
import jpabasic.securityjwt.entity.embadded.Password;
import lombok.*;

@Entity
@Builder
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "member")
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "user_id", nullable = false, unique = true)
    private String userId;
    @Embedded
    private Nickname nickname;
    @Embedded
    private Password password;
    @Embedded
    private Email email;
    @Enumerated(EnumType.STRING)
    private MemberRole role;
}
