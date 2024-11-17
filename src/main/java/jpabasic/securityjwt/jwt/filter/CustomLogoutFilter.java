//package jpabasic.securityjwt.jwt.filter;
//
//import com.hunmin.domain.repository.RefreshRepository;
//import io.jsonwebtoken.ExpiredJwtException;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.ServletRequest;
//import jakarta.servlet.ServletResponse;
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import jpabasic.securityjwt.jwt.util.JWTUtil;
//import org.springframework.web.filter.GenericFilterBean;
//
//import java.io.IOException;
//
//public class CustomLogoutFilter extends GenericFilterBean {
//
//    private final JWTUtil jwtUtil;
//    private final RefreshRepository refreshRepository;
//
//    public CustomLogoutFilter(JWTUtil jwtUtil, RefreshRepository refreshRepository) {
//        this.jwtUtil = jwtUtil;
//        this.refreshRepository = refreshRepository;
//    }
//
//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
//            throws IOException, ServletException {
//        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
//    }
//
//    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//            throws IOException, ServletException {
//
//        // 로그아웃 경로에서 오는 POST 요청인지 확인(아니라면 다음 필터로 넘어감)
//        String requestUri = request.getRequestURI();
//        String requestMethod = request.getMethod();
//        logger.info("=== Request URI: {}" + requestUri);
//        logger.info("=== Request Method: {}" + requestMethod);
//        if (!requestUri.matches("^\\/api/members/logout$") || !requestMethod.equals("POST")) {
//            chain.doFilter(request, response);
//            return;
//        }
//
//        // 쿠키에서 리프레시 토큰 확인
//        String refresh = null;
//        Cookie[] cookies = request.getCookies();
//        for (Cookie cookie : cookies) {
//            if (cookie.getName().equals("refresh")) {
//                refresh = cookie.getValue();
//            }
//        }
//
//        // refresh null check
//        if (refresh == null) {
//            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//            return;
//        }
//
//        // expired check
//        try {
//            jwtUtil.isExpired(refresh);
//        } catch (ExpiredJwtException e) {
//            //response status code
//            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//            return;
//        }
//
//        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
//        String category = jwtUtil.getCategory(refresh);
//        if (!category.equals("refresh")) {
//            //response status code
//            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//            return;
//        }
//
//        // DB에 토큰이 저정되어 있는지 확인
//        Boolean isExist = refreshRepository.existsByRefresh(refresh);
//        if (!isExist) {
//            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//            return;
//        }
//
//        // 로그아웃 진행
//        // db에서 refresh 토큰 제거
//        refreshRepository.deleteByRefresh(refresh);
//
//        // Refresh 토큰 Cookie 값 0
//        Cookie cookie = new Cookie("refresh", null);
//        cookie.setMaxAge(0);
//        cookie.setPath("/api/members");
//
//        response.addCookie(cookie);
//        response.setStatus(HttpServletResponse.SC_OK);
//        logger.info("===== 로그아웃 되었습니다.");
//    }
//}
//
