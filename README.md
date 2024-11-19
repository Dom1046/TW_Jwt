# TW_Jwt
토이프로젝트- jwt토큰 구현

1. 로그인시 (발급)
Access Token
Refresh Token 

2. 로그아웃시 (토큰 삭제/차단)
Access Token -> 차단
Refresh Token -> 삭제

3. Access 토큰 만료시
Access Token -> 재발급
Refresh Token -> 새로운 Token으로 변경

4. 두 토큰 모두 만료시
- 로그인 요청
