package jpabasic.securityjwt.config;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import redis.embedded.RedisExecProvider;
import redis.embedded.RedisServer;
import redis.embedded.util.OS;

import java.io.IOException;

@Log4j2
@Profile("local")
@Configuration
public class EmbeddedRedisConfig {

    @Value("${spring.redis.port}")
    private int redisPort;

    private RedisServer redisServer;

    @PostConstruct
    public void startRedis() throws IOException {
        if (redisServer == null || !redisServer.isActive()) {
            RedisExecProvider customProvider = RedisExecProvider.defaultProvider();

            // 운영체제에 맞는 Redis 서버 실행 파일 경로 설정
            if (System.getProperty("os.name").toLowerCase().contains("window")) {
                customProvider.override(OS.WINDOWS, "redis-server.exe");
            } else if (System.getProperty("os.name").toLowerCase().contains("mac")) {
                customProvider.override(OS.MAC_OS_X, "/usr/local/bin/redis-server");
            } else {
                customProvider.override(OS.UNIX, "/usr/bin/redis-server");
            }

            redisServer = RedisServer.builder()
                    .redisExecProvider(customProvider)
                    .port(redisPort)
                    .setting("maxmemory 128M")
                    .build();

            try {
                redisServer.start();
                log.info("Embedded Redis started on port: {}", redisPort);
            } catch (Exception e) {
                log.error("Could not start embedded Redis: {}", e.getMessage(), e);
                throw new RuntimeException("Failed to start embedded Redis server.", e);
            }
        }
    }

    @PreDestroy
    public void stopRedis() {
        if (redisServer != null && redisServer.isActive()) {
            redisServer.stop();
            log.info("Embedded Redis stopped.");
        }
    }
}
