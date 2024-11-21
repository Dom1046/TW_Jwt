package jpabasic.securityjwt.config;

import jpabasic.securityjwt.jwt.filter.JWTFilter;
import jpabasic.securityjwt.jwt.filter.LoginFilter;
import jpabasic.securityjwt.jwt.filter.LogoutFilter;
import jpabasic.securityjwt.jwt.util.JWTUtil;
import jpabasic.securityjwt.service.AccessTokenBlackList;
import jpabasic.securityjwt.service.RefreshTokenService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableWebSecurity
@Log4j2
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    @Value("${spring.jwt.access-token-validity-in-milliseconds}")
    private Long accessTokenValidity;
    @Value("${spring.jwt.refresh-token-validity-in-milliseconds}")
    private Long accessRefreshTokenValidity;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenBlackList accessTokenBlackList;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil, RefreshTokenService refreshTokenService, AccessTokenBlackList accessTokenBlackList) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.accessTokenBlackList = accessTokenBlackList;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authManager = authenticationManager(authenticationConfiguration);

        LoginFilter loginFilter = new LoginFilter(accessTokenValidity, accessRefreshTokenValidity, authManager, jwtUtil, refreshTokenService);
        loginFilter.setFilterProcessesUrl("/api/login");

        LogoutFilter logoutFilter = new LogoutFilter(accessTokenBlackList, jwtUtil, refreshTokenService);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable);
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join", "logout").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JWTFilter(jwtUtil, refreshTokenService, accessTokenValidity, accessRefreshTokenValidity, accessTokenBlackList), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(logoutFilter, JWTFilter.class);
        return http.build();
    }
}
