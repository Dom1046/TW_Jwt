package jpabasic.securityjwt.jwt.util;

import io.jsonwebtoken.Jwts;
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

    public String createJwt(Map<String, Object> valueMap, Long min) {
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
    }
    public Map<String, Object> validateToken(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload();
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

}
