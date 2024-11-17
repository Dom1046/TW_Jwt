package jpabasic.securityjwt.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jpabasic.securityjwt.entity.Member;
import jpabasic.securityjwt.entity.MemberRole;
import jpabasic.securityjwt.entity.TokenCategory;
import jpabasic.securityjwt.entity.embadded.Email;
import jpabasic.securityjwt.jwt.auth.CustomMemberDetails;
import jpabasic.securityjwt.jwt.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        if (requestURI.startsWith("/join") || requestURI.startsWith("/api/members/password/") || "/api/members/reissue".equals(requestURI)) {
            filterChain.doFilter(request, response);
            return;
        }
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String accessToken = authorizationHeader.substring(7);
            Map<String, Object> claims = jwtUtil.validateToken(accessToken);

            if (jwtUtil.isExpired(accessToken)) {
                handleException(response, new Exception("ACCESS TOKEN NOT FOUND"));
                return;
            }
            if (claims.get("category") == null || !((TokenCategory) claims.get("category")).equals(TokenCategory.ACCESS_TOKEN)) {
                handleException(response, new Exception("INVALID TOKEN CATEGORY"));
                return;
            }
            if (claims.get("userId") == null || claims.get("email") == null || claims.get("role") == null) {
                handleException(response, new Exception("INVALID TOKEN PAYLOAD"));
                return;
            }
            String userId = claims.get("userId").toString();
            Email email = (Email)claims.get("email");
            String role = claims.get("role").toString();
            Member member = Member.builder()
                    .userId(userId)
                    .email(email)
                    .role(MemberRole.valueOf(role))
                    .build();

            CustomMemberDetails customUserDetails = new CustomMemberDetails(member);
            Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authToken);
            filterChain.doFilter(request, response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    public void handleException(HttpServletResponse response, Exception e)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter()
                .println("{\"error\": \"" + e.getMessage() + "\"}");
    }
}