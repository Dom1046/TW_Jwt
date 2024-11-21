package jpabasic.securityjwt.service;

import jpabasic.securityjwt.jwt.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Log4j2
@Transactional
public class AccessTokenBlackList {

    @Autowired
    private JWTUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final RedisTemplate<String, Object> redisTemplate;
    private static final String ACCESS_KEY = "AccessToken";
    private static Long lastTime = 0L;

    public void registerBlackList(String AccessToken, String refreshToken) {
        try {
            Map<String, Object> payload = jwtUtil.validateToken(refreshToken);
            refreshTokenService.deleteRefreshTokenInRedis(payload);
            //5분 -> 300000밀리초 값비우기, 키는 유지
            if (nowTime() > lastTime + Duration.ofMinutes(5).toMillis()) {
                redisTemplate.delete(ACCESS_KEY);
            }
            redisTemplate.opsForSet().add(ACCESS_KEY, AccessToken);
            lastTime = nowTime();
            log.info("lastTime: {}", lastTime);
        } catch (Exception e) {
            log.error("로그아웃 블랙리스트에 실패하였습니다 :{}", e.getMessage());
            throw e;
        }
    }

    public boolean checkBlackList(String token) {
        try {
            return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(ACCESS_KEY, token));
        } catch (Exception e) {
            log.error("토큰 블랙리스트 확인에 실패하였습니다: {}", e.getMessage());
            throw e;
        }
    }

    private Long nowTime() {
        Date now = new Date();
        return now.getTime();
    }
}
