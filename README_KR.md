<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">DSL 기반의 간단한 YAML을 기초로한 빠른 맞춤형 취약점 스캐너</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/projectdiscovery/nuclei?filename=v2%2Fgo.mod">
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/downloads/projectdiscovery/nuclei/total">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases/"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/github/issues-raw/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/discussions"><img src="https://img.shields.io/github/discussions/projectdiscovery/nuclei">
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
</p>
      
<p align="center">
  <a href="#작동-방식">작동 방식</a> •
  <a href="#설치">설치</a> •
  <a href="#보안-엔지니어를-위한">보안 엔지니어를 위한</a> •
  <a href="#개발자를-위한">개발자를 위한</a> •
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/">문서</a> •
  <a href="#credits">Credits</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/faq">FAQs</a> •
  <a href="https://discord.gg/projectdiscovery"> Discord 참가</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">English</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">中文</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">한국어</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">스페인어</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_PT-BR.md">포르투갈어</a>
</p>

---

Nuclei는 템플릿을 기반으로 대상 간에 요청을 보내기 위해 사용되며 긍정 오류(false positives)가 0이고 다수의 호스트에서 빠른 스캔을 제공합니다. Nuclei는 TCP, DNS, HTTP, SSL, File, Whois, Websocket, Headless 등을 포함한 다양한 프로토콜의 스캔을 제공합니다. 강력하고 유연한 템플릿을 통해 Nuclei는 모든 종류의 보안 검사를 모델링 할 수 있습니다.

**300명 이상의** 보안 연구원과 엔지니어가 제공한 다양한 유형의 취약점 템플릿을 보관하는 [전용 저장소](https://github.com/projectdiscovery/nuclei-templates)를 보유하고 있습니다.



## 작동 방식

<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>


# 설치

Nuclei를 성공적으로 설치하기 위해서 **go1.22**가 필요합니다. 다음 명령을 실행하여 최신 버전을 설치합니다.

```sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**자세한 설치 방법은 [여기](https://nuclei.projectdiscovery.io/nuclei/get-started/)에서 찾을 수 있습니다.**

<table>
<tr>
<td>  

### Nuclei 템플릿

Nuclei는 [v2.5.2](https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2)부터 자동 템플릿 다운로드/업데이트를 기본으로 지원합니다.
[**Nuclei-Templates**](https://github.com/projectdiscovery/nuclei-templates) 프로젝트는 지속적으로 업데이트되는 즉시 사용 가능한 템플릿 목록을 제공합니다.

`update-templates` 플래그를 사용하여 언제든 템플릿을 업데이트할 수 있습니다. Nuclei의 [템플릿 가이드](https://nuclei.projectdiscovery.io/templating-guide/)에 따라 개별 워크플로 및 요구 사항에 대한 자체 검사를 작성할 수 있습니다.

YAML DSL의 참조 구문은 [여기](SYNTAX-REFERENCE.md)에서 확인할 수 있습니다.

</td>
</tr>
</table>

### 사용 방법

```sh
nuclei -h
```

도구에 대한 도움말이 표시됩니다. 다음은 지원하는 모든 스위치들입니다.


```console
Nuclei는 빠르고, 템플릿 기반의 취약점 스캐너로
넓은 설정 가능성, 대규모 확장성 및 사용 편의성에 중점을 두고 있습니다.

사용법:
  ./nuclei [flags]

TARGET:
   -u, -target string[]       스캔할 대상 URL/호스트
   -l, -list string           스캔할 대상 URL/호스트 목록이 있는 파일 경로 (한 줄에 하나씩)
   -resume string             resume.cfg를 사용하여 스캔 재개 (클러스터링은 비활성화됨)
   -sa, -scan-all-ips         dns 레코드와 관련된 모든 IP 스캔
   -iv, -ip-version string[]  스캔할 호스트의 IP 버전 (4,6) - (기본값 4)

TEMPLATES:
   -nt, -new-templates                    최신 nuclei-templates 릴리스에 추가된 새 템플릿만 실행
   -ntv, -new-templates-version string[]  특정 버전에 추가된 새 템플릿 실행
   -as, -automatic-scan                   wappalyzer 기술 감지를 사용하여 태그 매핑으로 자동 웹 스캔
   -t, -templates string[]                실행할 템플릿 또는 템플릿 디렉토리 목록 (쉼표로 구분, 파일)
   -turl, -template-url string[]          실행할 템플릿 url 또는 템플릿 url 목록 (쉼표로 구분, 파일)
   -w, -workflows string[]                실행할 워크플로우 또는 워크플로우 디렉토리 목록 (쉼표로 구분, 파일)
   -wurl, -workflow-url string[]          실행할 워크플로우 url 또는 워크플로우 url 목록 (쉼표로 구분, 파일)
   -validate                              nuclei에 전달된 템플릿 검증
   -nss, -no-strict-syntax                템플릿에서 엄격한 구문 검사 비활성화
   -td, -template-display                 템플릿 내용 표시
   -tl                                    사용 가능한 모든 템플릿 목록
   -sign                                  NUCLEI_SIGNATURE_PRIVATE_KEY 환경 변수에서 정의된 개인 키로 템플릿에 서명
   -code                                  코드 프로토콜 기반 템플릿 로딩 활성화

FILTERING:
   -a, -author string[]               저자를 기반으로 실행할 템플릿 (쉼표로 구분, 파일)
   -tags string[]                     태그를 기반으로 실행할 템플릿 (쉼표로 구분, 파일)
   -etags, -exclude-tags string[]     태그를 기반으로 제외할 템플릿 (쉼표로 구분, 파일)
   -itags, -include-tags string[]     기본값 또는 구성에 의해 제외되더라도 실행되어야 하는 태그
   -id, -template-id string[]         템플릿 id를 기반으로 실행할 템플릿 (쉼표로 구분, 파일, 와일드카드 허용)
   -eid, -exclude-id string[]         템플릿 id를 기반으로 제외할 템플릿 (쉼표로 구분, 파일)
   -it, -include-templates string[]   기본값 또는 구성에 의해 제외되더라도 실행되어야 하는 템플릿
   -et, -exclude-templates string[]   제외할 템플릿 또는 템플릿 디렉토리 (쉼표로 구분, 파일)
   -em, -exclude-matchers string[]    결과에서 제외할 템플릿 매처
   -s, -severity value[]              심각도를 기반으로 실행할 템플릿. 가능한 값: info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]     심각도를 기반으로 제외할 템플릿. 가능한 값: info, low, medium, high, critical, unknown
   -pt, -type value[]                 프로토콜 유형을 기반으로 실행할 템플릿. 가능한 값: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        프로토콜 유형을 기반으로 제외할 템플릿. 가능한 값: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  표현식 조건을 기반으로 실행할 템플릿

OUTPUT:
   -o, -output string            발견된 문제/취약점을 작성할 출력 파일
   -sresp, -store-resp           모든 요청/응답을 nuclei를 통해 출력 디렉토리에 저장
   -srd, -store-resp-dir string  모든 요청/응답을 nuclei를 통해 사용자 정의 디렉토리에 저장 (기본값 "output")
   -silent                       결과만 표시
   -nc, -no-color                출력 내용 색상 비활성화 (ANSI 이스케이프 코드)
   -j, -jsonl                    JSONL(ines) 형식으로 출력 작성
   -irr, -include-rr -omit-raw   JSON, JSONL, Markdown 출력에 요청/응답 쌍 포함 (결과만 해당) [사용 중단 -omit-raw 사용] (기본값 true)
   -or, -omit-raw                JSON, JSONL, Markdown 출력에서 요청/응답 쌍 생략 (결과만 해당)
   -ot, -omit-template           JSON, JSONL 출력에서 인코딩된 템플릿 생략
   -nm, -no-meta                 CLI 출력에서 결과 메타데이터 인쇄 비활성화
   -ts, -timestamp               CLI 출력에 타임스탬프 인쇄 활성화
   -rdb, -report-db string       nuclei 보고 데이터베이스 (보고 데이터를 유지하려면 항상 이것을 사용)
   -ms, -matcher-status          매치 실패 상태 표시
   -me, -markdown-export string  Markdown 형식으로 결과를 내보낼 디렉토리
   -se, -sarif-export string     SARIF 형식으로 결과를 내보낼 파일
   -je, -json-export string      JSON 형식으로 결과를 내보낼 파일
   -jle, -jsonl-export string    JSONL(ine) 형식으로 결과를 내보낼 파일

CONFIGURATIONS:
   -config string                        nuclei 구성 파일 경로
   -fr, -follow-redirects                http 템플릿에 대한 리디렉션 따라가기 활성화
   -fhr, -follow-host-redirects          같은 호스트에서 리디렉션 따라가기
   -mr, -max-redirects int               http 템플릿에 대해 따라갈 최대 리디렉션 수 (기본값 10)
   -dr, -disable-redirects               http 템플릿에 대한 리디렉션 비활성화
   -rc, -report-config string            nuclei 보고 모듈 구성 파일
   -H, -header string[]                  모든 http 요청에 포함할 사용자 정의 헤더/쿠키 (header:value 형식) (cli, file)
   -V, -var value                        key=value 형식의 사용자 정의 변수
   -r, -resolvers string                 nuclei에 대한 리졸버 목록이 있는 파일
   -sr, -system-resolvers                오류 대체로 시스템 DNS 해결 사용
   -dc, -disable-clustering              요청 클러스터링 비활성화
   -passive                              수동 HTTP 응답 처리 모드 활성화
   -fh2, -force-http2                    요청에 http2 연결 강제
   -ev, -env-vars                        템플릿에서 환경 변수 사용 활성화
   -cc, -client-cert string              스캔 대상 호스트에 대한 인증에 사용되는 클라이언트 인증서 파일 (PEM 인코딩)
   -ck, -client-key string               스캔 대상 호스트에 대한 인증에 사용되는 클라이언트 키 파일 (PEM 인코딩)
   -ca, -client-ca string                스캔 대상 호스트에 대한 인증에 사용되는 클라이언트 인증서 기관 파일 (PEM 인코딩)
   -sml, -show-match-line                파일 템플릿에 대한 매치 라인 표시, 추출기만 작동
   -ztls                                 ztls 라이브러리 사용, tls13에 대한 표준 하나로 자동 대체 [사용 중단] 자동 대체는 기본적으로 ztls로 활성화됨
   -sni string                           사용할 tls sni 호스트 이름 (기본값: 입력 도메인 이름)
   -lfa, -allow-local-file-access        시스템 어디에서나 파일 (페이로드) 액세스 허용
   -lna, -restrict-local-network-access  로컬 / 개인 네트워크로의 연결 차단
   -i, -interface string                 네트워크 스캔에 사용할 네트워크 인터페이스
   -at, -attack-type string              수행할 페이로드 조합 유형 (batteringram,pitchfork,clusterbomb)
   -sip, -source-ip string               네트워크 스캔에 사용할 소스 IP 주소
   -rsr, -response-size-read int         바이트 단위로 읽을 최대 응답 크기 (기본값 10485760)
   -rss, -response-size-save int         바이트 단위로 읽을 최대 응답 크기 (기본값 1048576)
   -reset                                reset은 모든 nuclei 구성 및 데이터 파일을 제거합니다 (nuclei-templates 포함)
   -tlsi, -tls-impersonate               실험적인 클라이언트 hello (ja3) tls 무작위화 활성화

INTERACTSH:
   -iserver, -interactsh-server string  자체 호스팅 인스턴스를 위한 interactsh 서버 url (기본값: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    자체 호스팅 interactsh 서버를 위한 인증 토큰
   -interactions-cache-size int         상호 작용 캐시에 유지할 요청 수 (기본값 5000)
   -interactions-eviction int           캐시에서 요청을 제거하기 전에 기다릴 초 수 (기본값 60)
   -interactions-poll-duration int      각 상호 작용 폴 요청 사이에 기다릴 초 수 (기본값 5)
   -interactions-cooldown-period int    종료 전에 상호 작용 폴링에 추가 시간 (기본값 5)
   -ni, -no-interactsh                  OAST 테스트를 위한 interactsh 서버 비활성화, OAST 기반 템플릿 제외

FUZZING:
   -ft, -fuzzing-type string  템플릿에 설정된 퍼징 유형 재정의 (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string  템플릿에 설정된 퍼징 모드 재정의 (multiple, single)

UNCOVER:
   -uc, -uncover                  uncover 엔진 활성화
   -uq, -uncover-query string[]   uncover 검색 쿼리
   -ue, -uncover-engine string[]  uncover 검색 엔진 (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow) (기본값 shodan)
   -uf, -uncover-field string     반환할 uncover 필드 (ip,port,host) (기본값 "ip:port")
   -ul, -uncover-limit int        반환할 uncover 결과 (기본값 100)
   -ur, -uncover-ratelimit int    알려지지 않은 ratelimit의 엔진을 재정의하는 ratelimit (기본값 60 req/min) (기본값 60)

RATE-LIMIT:
   -rl, -rate-limit int               초당 보낼 최대 요청 수 (기본값 150)
   -rlm, -rate-limit-minute int       분당 보낼 최대 요청 수
   -bs, -bulk-size int                템플릿당 병렬로 분석할 최대 호스트 수 (기본값 25)
   -c, -concurrency int               병렬로 실행할 최대 템플릿 수 (기본값 25)
   -hbs, -headless-bulk-size int      템플릿당 병렬로 분석할 최대 headless 호스트 수 (기본값 10)
   -headc, -headless-concurrency int  병렬로 실행할 최대 headless 템플릿 수 (기본값 10)

OPTIMIZATIONS:
   -timeout int                     타임아웃 전에 기다릴 초 수 (기본값 10)
   -retries int                     실패한 요청을 재시도하는 횟수 (기본값 1)
   -ldp, -leave-default-ports       기본 HTTP/HTTPS 포트 남겨두기 (예: host:80,host:443)
   -mhe, -max-host-error int        스캔에서 건너뛰기 전에 호스트에서 허용되는 최대 오류 수 (기본값 30)
   -te, -track-error string[]       최대 호스트 오류 감시 목록에 주어진 오류 추가 (표준, 파일)
   -nmhe, -no-mhe                   오류를 기반으로 스캔에서 호스트 건너뛰기 비활성화
   -project                         동일한 요청을 여러 번 보내는 것을 피하기 위해 프로젝트 폴더 사용
   -project-path string             특정 프로젝트 경로 설정 (기본값 "/tmp")
   -spm, -stop-at-first-match       첫 번째 매치 후 HTTP 요청 처리 중지 (템플릿/워크플로우 로직이 깨질 수 있음)
   -stream                          스트림 모드 - 입력 정렬 없이 시작
   -ss, -scan-strategy value        스캔하는 동안 사용할 전략(auto/host-spray/template-spray) (기본값 auto)
   -irt, -input-read-timeout value  입력 읽기 시간 초과 (기본값 3m0s)
   -nh, -no-httpx                   비 URL 입력에 대한 httpx 프로브 비활성화
   -no-stdin                        stdin 처리를 비활성화합니다

HEADLESS:
   -headless                        headless 브라우저 지원이 필요한 템플릿 활성화 (Linux의 root 사용자는 샌드박스 비활성화)
   -page-timeout int                headless 모드에서 각 페이지를 기다리는 시간(초) (기본값 20)
   -sb, -show-browser               headless 모드로 실행하는 템플릿에서 브라우저 화면 표시
   -ho, -headless-options string[]  추가 옵션으로 headless chrome 시작
   -sc, -system-chrome              nuclei가 설치한 Chrome 대신 로컬에 설치된 Chrome 브라우저 사용
   -lha, -list-headless-action      사용 가능한 headless 액션 목록 표시

DEBUG:
   -debug                    모든 요청과 응답 표시
   -dreq, -debug-req         보낸 모든 요청 표시
   -dresp, -debug-resp       받은 모든 응답 표시
   -p, -proxy string[]       사용할 http/socks5 프록시 목록 (쉼표로 구분하거나 파일 입력)
   -pi, -proxy-internal      모든 내부 요청을 프록시를 통해 전송
   -ldf, -list-dsl-function  지원되는 모든 DSL 함수 시그니처 목록 표시
   -tlog, -trace-log string  보낸 요청 추적 로그를 기록할 파일
   -elog, -error-log string  보낸 요청 오류 로그를 기록할 파일
   -version                  nuclei 버전 표시
   -hm, -hang-monitor        nuclei 멈춤 모니터링 활성화
   -v, -verbose              자세한 출력 표시
   -profile-mem string       선택적인 nuclei 메모리 프로필 덤프 파일
   -vv                       스캔에 로드된 템플릿 표시
   -svd, -show-var-dump      디버깅을 위한 변수 덤프 표시
   -ep, -enable-pprof        pprof 디버깅 서버 활성화
   -tv, -templates-version   설치된 nuclei-templates의 버전 표시
   -hc, -health-check        진단 검사 실행

UPDATE:
   -up, -update                      최신 릴리스 버전으로 nuclei 엔진 업데이트
   -ut, -update-templates            최신 릴리스 버전으로 nuclei-templates 업데이트
   -ud, -update-template-dir string  nuclei-templates를 설치/업데이트할 사용자 지정 디렉토리
   -duc, -disable-update-check       자동 nuclei/templates 업데이트 확인 비활성화

STATISTICS:
   -stats                    실행 중인 스캔에 대한 통계 표시
   -sj, -stats-json          JSONL(ines) 형식으로 통계 표시
   -si, -stats-interval int  통계 업데이트를 표시하기까지 기다릴 초 수 (기본값 5)
   -mp, -metrics-port int    nuclei 메트릭스를 노출할 포트 (기본값 9092)

CLOUD:
   -auth                  projectdiscovery 클라우드 (pdcp) API 키 구성
   -cup, -cloud-upload    스캔 결과를 pdcp 대시보드에 업로드
   -sid, -scan-id string  주어진 스캔 ID에 스캔 결과 업로드


예시:
단일 호스트에서 nuclei 실행:
	$ nuclei -target example.com

특정 템플릿 디렉토리로 nuclei 실행:
	$ nuclei -target example.com -t http/cves/ -t ssl

호스트 목록에 대해 nuclei 실행:
	$ nuclei -list hosts.txt

JSON 출력으로 nuclei 실행:
	$ nuclei -target example.com -json-export output.json

정렬된 Markdown 출력으로 nuclei 실행 (환경 변수 사용):
	$ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

추가 문서는 여기에서 확인할 수 있습니다: https://docs.nuclei.sh/getting-started/running
```

### Nuclei 실행

[community-curated](https://github.com/projectdiscovery/nuclei-templates) nuclei 템플릿으로 대상 도메인을 스캔합니다.

```sh
nuclei -u https://example.com
```

[community-curated](https://github.com/projectdiscovery/nuclei-templates) nuclei 템플릿으로 대상 URL들을 스캔합니다.

```sh
nuclei -list urls.txt
```

`urls.txt`의 예시:

```yaml
http://example.com
http://app.example.com
http://test.example.com
http://uat.example.com
```

**nuclei를 실행하는 자세한 예는 [여기](https://nuclei.projectdiscovery.io/nuclei/get-started/#running-nuclei)에서 찾을 수 있습니다.**

# 보안 엔지니어를 위한

Nuclei는 보안 엔지니어가 조직에서 워크플로를 커스텀하는 데 도움이 되는 많은 기능을 제공합니다.
다양한 스캔 기능(DNS, HTTP, TCP 등)을 통해 보안 엔지니어는 Nuclei를 사용하여 맞춤형 검사 세트를 쉽게 만들 수 있습니다.

- 다양한 프로토콜 지원: TCP, DNS, HTTP, File, etc
- 워크플로 및 [동적 요청](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)을 통한 복잡한 취약점 탐색 달성
- CI/CD에 쉽게 통합할 수 있으며, 회귀 주기에 쉽게 통합되어 취약점의 수정 및 재출현을 능동적으로 확인할 수 있도록 설계됨.

<h1 align="left">
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

<table>
<tr>
<td>  

**Bug Bounty hunter들을 위해:**

Nuclei를 사용하면 자체 검사 모음으로 테스트 접근 방식을 사용자 정의하고 버그 바운티 프로그램에서 쉽게 실행할 수 있습니다.
또한 Nuclei는 모든 연속 스캔 워크플로에 쉽게 통합될 수 있습니다.

- 다른 도구 워크플로에 쉽게 통합되도록 설계됨.
- 몇 분 안에 수천 개의 호스트를 처리할 수 있음.
- 간단한 YAML DSL로 사용자 지정 테스트 접근 방식을 쉽게 자동화할 수 있음.

버그 바운티 워크플로에 맞는 다른 오픈 소스 프로젝트를 확인할 수 있습니다.: [github.com/projectdiscovery](http://github.com/projectdiscovery), 또한, 우리는 매일 [Chaos에서 DNS 데이터를 갱신해 호스팅합니다](http://chaos.projectdiscovery.io).

</td>
</tr>
</table>

<table>
<tr>
<td>
  
**침투 테스터들을 위해:**

Nuclei는 수동적이고 반복적인 프로세스를 보강하여 보안 평가에 접근하는 방식을 크게 개선합니다.
컨설턴트들은 이미 Nuclei를 사용해 수동 평가 단계를 전환하고 있으며 이를 통해 수천 개의 호스트에서 자동화된 방식으로 맞춤형 평가 접근 방식을 실행할 수 있습니다.

침투 테스터는 평가 프로세스, 특히 수정 사항을 쉽게 확인할 수 있는 회귀 주기를 통해 공개 템플릿 및 사용자 지정 기능을 최대한 활용할 수 있습니다.

- 규정 준수, 표준 제품군(예: OWASP Top 10) 체크리스트 쉽게 생성.
- Nuclei의 [fuzz](https://nuclei.projectdiscovery.io/templating-guide/protocols/http-fuzzing/) 및 [workflows](https://nuclei.projectdiscovery.io/templating-guide/workflows/) 같은 기능으로 복잡한 수동 단계와 반복 평가를 쉽게 자동화할 수 있음.
- 템플릿 재실행으로 취약점 수정 재테스트 용이.

</td>
</tr>
</table>


# 개발자를 위한

Nuclei는 단순성을 염두에 두고 구축되었으며 수백 명의 보안 연구원들이 지원하는 커뮤니티 템플릿을 사용하여 호스트에서 지속적인 Nuclei 스캔을 사용하여 최신 보안 위협에 대한 업데이트를 유지할 수 있습니다.

수정 사항을 검증하고 향후 발생하는 취약점을 제거하기 위해 회귀 테스트 주기에 쉽게 통합되도록 설계되었습니다.

- **CI/CD:** 엔지니어들은 이미 CI/CD 파이프라인 내에서 Nuclei를 활용하고 있으며 이를 통해 맞춤형 템플릿으로 스테이징 및 프로덕션 환경을 지속적으로 모니터링할 수 있습니다.
- **Continuous Regression Cycle:** Nuclei를 사용하면 새로 식별된 모든 취약점에 대한 사용자 지정 템플릿을 만들고 Nuclei 엔진에 넣어 지속적인 회귀 주기에서 제거할 수 있습니다.

[이 문제에 대한 논의 스레드](https://github.com/projectdiscovery/nuclei-templates/discussions/693)가 있으며, Nuclei 템플릿을 작성해 제출할 때마다 해커에게 인센티브를 제공하는 버그 바운티 프로그램들이 존재합니다. 이 프로그램은 모든 자산에서 취약점을 제거할 뿐만 아니라 미래에 프로덕션에 다시 등장할 위험을 제거할 수 있도록 도와줍니다.
이것을 당신의 조직에서 구현하는 것에 관심이 있다면 언제든지 [저희에게 연락하십시오](mailto:contact@projectdiscovery.io).
시작하는 과정에서 기꺼이 도와드리거나 [도움이 필요한 경우 논의 스레드](https://github.com/projectdiscovery/nuclei-templates/discussions/693)에 게시할 수도 있습니다.

<h3 align="center">
  <img src="static/regression-with-nuclei.jpg" alt="regression-cycle-with-nuclei" width="1100px"></a>
</h3>

<h1 align="left">
  <a href="https://github.com/projectdiscovery/nuclei-action"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

### Resources

- [Finding bugs with Nuclei with PinkDraconian (Robbe Van Roey)](https://www.youtube.com/watch?v=ewP0xVPW-Pk) by **[@PinkDraconian](https://twitter.com/PinkDraconian)** 
- [Nuclei: Packing a Punch with Vulnerability Scanning](https://bishopfox.com/blog/nuclei-vulnerability-scan) by **Bishopfox**
- [The WAF efficacy framework](https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf) by **Fastly**
- [Scanning Live Web Applications with Nuclei in CI/CD Pipeline](https://blog.escape.tech/devsecops-part-iii-scanning-live-web-applications/) by **[@TristanKalos](https://twitter.com/TristanKalos)**
- [Community Powered Scanning with Nuclei](https://blog.projectdiscovery.io/community-powered-scanning-with-nuclei/)
- [Nuclei Unleashed - Quickly write complex exploits](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)
- [Nuclei - Fuzz all the things](https://blog.projectdiscovery.io/nuclei-fuzz-all-the-things/)
- [Nuclei + Interactsh Integration for Automating OOB Testing](https://blog.projectdiscovery.io/nuclei-interactsh-integration/)
- [Weaponizes nuclei Workflows to Pwn All the Things](https://medium.com/@dwisiswant0/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) by **[@dwisiswant0](https://github.com/dwisiswant0)**
- [How to Scan Continuously with Nuclei?](https://medium.com/@dwisiswant0/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) by **[@dwisiswant0](https://github.com/dwisiswant0)**
- [Hack with Automation !!!](https://dhiyaneshgeek.github.io/web/security/2021/07/19/hack-with-automation/) by **[@DhiyaneshGeek](https://github.com/DhiyaneshGeek)**

### Credits

Thanks to all the amazing community [contributors for sending PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors). Do also check out the below similar open-source projects that may fit in your workflow:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### License

Nuclei is distributed under [MIT License](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://nuclei.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
