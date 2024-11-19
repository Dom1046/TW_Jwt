package jpabasic.securityjwt.jwt.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import jpabasic.securityjwt.entity.TokenCategory;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.Map;

@Log4j2
@Component
public class JWTUtil {

    private final SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secretKey}")String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String createAccessToken(Map<String, Object> valueMap, Long min) {
        Date now = new Date();
        return Jwts.builder().header().add("alg", "HS256").add("type", "JWT")
                .and()
                .claims(valueMap)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(       //토큰 만료 시간
                        new Date( now.getTime() +
                                Duration.ofMinutes(min).toMillis()))
                .signWith(secretKey)
                .compact();
    }
    public String createRefreshToken(Map<String, Object> valueMap, Long min) {
        try{
            Date now = new Date();
        return Jwts.builder().header().add("alg", "HS256").add("type", "JWT")
                .and()
                .claims(valueMap)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(       //토큰 만료 시간
                        new Date( now.getTime() +
                                Duration.ofMinutes(min).toMillis()) )
                .signWith(secretKey)
                .compact();
        }catch(Exception e){
            log.error("리프레시 토큰 생성 실패: {}",e.getMessage());
            throw e;
        }
    }
    public Map<String, Object> validateToken(String token) {
        try{
            return Jwts.parser().verifyWith(secretKey).build()
                    .parseSignedClaims(token).getPayload();
        }catch (ExpiredJwtException e){
            log.error("토큰이 만료되었어요: {}, token {}", e.getMessage(), token);
            return e.getClaims();
        }catch (Exception e){
            log.error("토큰 유효성검사 실패 : {}, token {}", e.getMessage(), token);
            throw e;
        }
    }

    public Boolean isExpired(String token) {
        try {
            return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
        }catch(ExpiredJwtException e){
            log.error("토큰이 만료되었어요 : {}, token {}", e.getMessage(), token);
            return e.getClaims().getExpiration().before(new Date());
        }catch (Exception e){
            log.error("토큰 만료확인 실패 : {}, token {}", e.getMessage(), token);
            throw e;
        }
    }
}
