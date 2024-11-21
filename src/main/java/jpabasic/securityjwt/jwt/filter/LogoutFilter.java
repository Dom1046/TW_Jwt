package jpabasic.securityjwt.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jpabasic.securityjwt.jwt.util.JWTUtil;
import jpabasic.securityjwt.service.AccessTokenBlackList;
import jpabasic.securityjwt.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class LogoutFilter extends OncePerRequestFilter {

    private final AccessTokenBlackList accessTokenBlackList;
    private final JWTUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getRequestURI().equals("/api/logout");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Refresh Token 없을 때
        String refreshTokenFromCookies = getRefreshTokenFromCookies(request);
        if (refreshTokenFromCookies == null || refreshTokenFromCookies.trim().isEmpty()) {
            log.warn("No refresh token found");
            handleErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Refresh Token is missing");
            return;
        }

        // Access Token 없을 때
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            log.warn("No access token found");
            handleErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Access Token is missing");
            return;
        }

        String accessToken = authorizationHeader.substring(7);
        // 블랙리스트 등록
        try {
            if (!jwtUtil.isExpired(accessToken)) {
                if (!jwtUtil.isExpired(refreshTokenFromCookies)) {
                    accessTokenBlackList.registerBlackList(accessToken, refreshTokenFromCookies);
                    log.info("Tokens are registered to BlackList");
                } else {
                    log.info("RefreshToken is expired");
                }
            } else {
                log.info("AccessToken is expired");

            }
            Map<String, Object> payloadRefresh = jwtUtil.validateToken(refreshTokenFromCookies);
            refreshTokenService.deleteRefreshTokenInRedis(payloadRefresh);

        } catch (Exception e) {
            log.error("토큰 블랙리스트 처리에 실패하였습니다 : {}", e.getMessage());
            handleErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Token processing failed");
            return;
        }
        // 쿠키 비우기
        Cookie cookie = new Cookie("refreshToken", null);
//        cookie.setSecure(true); // HTTPS 환경에서만 전송
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write("{\"message\": \"Logout successful\"}");
        response.getWriter().flush();
    }

    // 리프레시 토큰 꺼내기
    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    // 에러 응답에 등록하기
    private void handleErrorResponse(HttpServletResponse response, int statusCode, String message) throws IOException {
        response.setStatus(statusCode);
        response.setContentType("application/json");
        response.getWriter().write(String.format("{\"error\": \"%s\"}", message));
        response.getWriter().flush();
    }
}