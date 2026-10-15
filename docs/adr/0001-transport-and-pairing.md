# ADR-0001 전송과 페어링: 핀 고정 WSS + HMAC 소지 증명 + PC 확인

- 상태: 승인됨 (2026-10-15)
- 관련: `docs/security.md` §3–§5, `docs/protocol.md` §1, §4.1–4.5

## 맥락

PRD §6은 "같은 Wi-Fi", "QR 등록", "암호화 통신", "기기 폐기 가능"을 요구한다. 초안은 자가서명 인증서 지문 + 1회용 페어링 토큰 + 베어러 디바이스 토큰이었다. 심사에서 (1) 인증서 전체 지문은 IP SAN 변경·갱신 때 재페어링을 강요하고, (2) QR 토큰 소지만으로 등록되면 QR을 촬영한 같은 LAN의 공격자(A4)가 120초 경쟁에서 이길 수 있으며, (3) 보안 우선안의 EC 키쌍 챌린지-응답 + ECDSA 결정 서명은 Phase 1 빌드 비용(크로스 언어 canonical 인코더, 2단계 CI 서명 벡터, 실기 Keystore 검증)이 크다는 점이 지적되었다. Android 리서치는 OkHttp가 자가서명을 `CertificatePinner`만으로 신뢰할 수 없고 커스텀 `X509TrustManager`가 필요하며, SPKI 핀이면 같은 키쌍 재발급에 영향이 없음을 확인했다.

## 결정

1. **단일 WSS**(`wss://<lan-ip>:47832/v1/link`, rustls 0.23 ring, rcgen 0.14 ECDSA P-256). 평문 `ws://`·HTTP 폴링·mDNS 없음. 서버 키쌍은 재사용하고 인증서만 재발급한다.
2. **QR에는 SPKI SHA-256 핀**(OkHttp `sha256/` 형식). 폰은 리프 SPKI가 핀과 정확히 일치할 때만 신뢰(`SpkiPinTrustManager` + `HostnameVerifier` + `CertificatePinner`).
3. **페어링 = HMAC 소지 증명 + SAS + PC 화면 승인.** `pairing_secret`(32B, 120초, 1회, 3회 실패 소각)은 QR에만 있고 와이어에 실리지 않는다. 폰은 `HMAC-SHA256(secret, canonical_pair_bytes)`를 보내고, PC는 검증 후 6자리 SAS를 양쪽에 표시하며 사용자가 PC에서 [승인]해야 등록된다. 폰 EC P-256 공개키도 이때 등록한다.
4. **접속 인증은 Phase 1에서 디바이스 토큰**(32B; PC는 해시만, 폰은 Keystore AES-GCM 래핑) + 연결별 `challenge` 에코. 결정 ECDSA 서명·`hello` 서명은 Phase 3 (공개키는 이미 등록되어 재페어링 불필요).
5. 인증 전 연결은 `challenge` 한 프레임만 받고 5초 내 `pair`/`hello`가 없으면 닫힌다. 인증 실패는 원인 비구분·1초 지연.

## 결과

- (+) 인증서 갱신·IP 변경이 재페어링을 요구하지 않는다. QR 촬영 공격은 PC 확인 단계에서 차단된다. 비밀이 와이어·DB에 평문으로 존재하지 않는다(해시·HMAC).
- (+) 폰 측 암호 작업은 HMAC-SHA256(JVM 표준)뿐이라 `android/core`에서 JVM 테스트가 가능하고, Rust·Kotlin 공유 벡터는 `pair` 하나로 충분하다.
- (−) PC 측에 SAS 모달 UI가 추가되고 페어링 흐름이 한 단계 길어진다. 사용자가 모달을 보지 않고 승인하는 위험은 남는다(승인 버튼 2초 지연, `retype_sas` 강화 옵션으로 완화).
- (−) `decision.auth`가 Phase 1에서는 폰의 주장이다(`security.md` §6.4에 한계 명시, Phase 3에서 서명으로 해소).
- 대안 기각: 베어러 토큰 + PC 확인 없음(A4 취약), 전체 ECDSA 체계 즉시 도입(Phase 1 비용), 평문 WS + 앱 계층 Noise(두 번째 암호 계층·검증 부담).
