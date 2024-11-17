package jpabasic.securityjwt.jwt.auth;

import jpabasic.securityjwt.entity.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@RequiredArgsConstructor
public class CustomMemberDetails implements UserDetails {

    private final Member member;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add((GrantedAuthority) () -> member.getRole().name());
        return collection;
    }

    public String getEmail(){
        return member.getEmail().getValue();
    }

    public String getUserId(){
        return member.getUserId();
    }
    @Override
    public String getPassword() {
        return member.getPassword().getValue();
    }

    @Override
    public String getUsername() {
        return member.getNickname().getValue();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}