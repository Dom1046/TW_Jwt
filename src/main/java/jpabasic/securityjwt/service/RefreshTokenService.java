package jpabasic.securityjwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.NoSuchElementException;

@Service
@RequiredArgsConstructor
@Transactional
@Log4j2
public class RefreshTokenService {

    private final RedisTemplate<String, Object> redisTemplate;
    protected static final String REFRESH_KEY = "RefreshToken";

    public void insertInRedis(Map<String, Object> payloadMap, String refreshToken) {

        try {
            if (refreshToken != null) {
                deleteRefreshTokenInRedis(payloadMap);
            }
            deleteRefreshTokenInRedis(payloadMap);
            redisTemplate.opsForHash().put(REFRESH_KEY, makeHashKey(payloadMap), refreshToken);
        } catch (Exception e) {
            log.error("redis failed to creat refreshToken :{}", e.getMessage());
        }
    }

    public String readRefreshTokenInRedis(Map<String, Object> payloadMap) {
        try {
            String refreshToken = (String) redisTemplate.opsForHash().get(REFRESH_KEY, makeHashKey(payloadMap));
            if (refreshToken == null) {
                log.warn("No refreshToken found for userId: {}", payloadMap);
                throw new NoSuchElementException("No refresh token found for userId: " + payloadMap);
            }
            return refreshToken;
        } catch (Exception e) {
            log.error("redis failed to read refreshToken :{}", e.getMessage());
        }
        return null;
    }

    public void deleteRefreshTokenInRedis(Map<String, Object> payloadMap) {
        try {
            redisTemplate.opsForHash().delete(REFRESH_KEY, makeHashKey(payloadMap));
        } catch (Exception e) {
            log.error("redis failed to delete refreshToken :{}", e.getMessage());
        }
    }
    // 회원 데이터 마다 다른 키값 만들기
    public String makeHashKey(Map<String, Object> payloadMap) {
        Object userId = payloadMap.get("userId");
        Object email = payloadMap.get("email");
        Object role = payloadMap.get("role");
        Object category = payloadMap.get("category");
        return userId + ":" + email + ":" + role + ":" + category;
    }
}
