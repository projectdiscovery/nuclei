module github.com/projectdiscovery/nuclei/v3

go 1.21

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/alecthomas/jsonschema v0.0.0-20211022214203-8b29eab41725
	github.com/andygrunwald/go-jira v1.16.0
	github.com/antchfx/htmlquery v1.3.0
	github.com/bluele/gcache v0.0.2
	github.com/corpix/uarand v0.2.0
	github.com/go-playground/validator/v10 v10.14.1
	github.com/go-rod/rod v0.114.0
	github.com/gobwas/ws v1.2.1
	github.com/google/go-github v17.0.0+incompatible
	github.com/itchyny/gojq v0.12.13
	github.com/json-iterator/go v1.1.12
	github.com/julienschmidt/httprouter v1.3.0
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/miekg/dns v1.1.56
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/clistats v0.0.19
	github.com/projectdiscovery/fastdialer v0.0.40
	github.com/projectdiscovery/hmap v0.0.22
	github.com/projectdiscovery/interactsh v1.1.7
	github.com/projectdiscovery/rawhttp v0.1.23
	github.com/projectdiscovery/retryabledns v1.0.39
	github.com/projectdiscovery/retryablehttp-go v1.0.32
	github.com/projectdiscovery/yamldoc-go v1.0.4
	github.com/remeh/sizedwaitgroup v1.0.0
	github.com/rs/xid v1.5.0
	github.com/segmentio/ksuid v1.0.4
	github.com/shirou/gopsutil/v3 v3.23.7 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/cast v1.5.1
	github.com/syndtr/goleveldb v1.0.0
	github.com/valyala/fasttemplate v1.2.2
	github.com/weppos/publicsuffix-go v0.30.2-0.20230730094716-a20f9abcc222
	github.com/xanzy/go-gitlab v0.84.0
	go.uber.org/multierr v1.11.0
	golang.org/x/net v0.17.0
	golang.org/x/oauth2 v0.11.0
	golang.org/x/text v0.13.0
	gopkg.in/yaml.v2 v2.4.0
	moul.io/http2curl v1.0.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.3.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.1.0
	github.com/DataDog/gostackparse v0.6.0
	github.com/Masterminds/semver/v3 v3.2.1
	github.com/Mzack9999/gcache v0.0.0-20230410081825-519e28eab057
	github.com/antchfx/xmlquery v1.3.15
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	github.com/aws/aws-sdk-go-v2 v1.19.0
	github.com/aws/aws-sdk-go-v2/config v1.18.28
	github.com/aws/aws-sdk-go-v2/credentials v1.13.27
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.72
	github.com/aws/aws-sdk-go-v2/service/s3 v1.37.0
	github.com/charmbracelet/glamour v0.6.0
	github.com/denisenkom/go-mssqldb v0.12.3
	github.com/ditashi/jsbeautifier-go v0.0.0-20141206144643-2520a8026a9c
	github.com/docker/go-units v0.5.0
	github.com/dop251/goja v0.0.0-20230828202809-3dbe69dd2b8e
	github.com/fatih/structs v1.1.0
	github.com/go-git/go-git/v5 v5.7.0
	github.com/go-ldap/ldap/v3 v3.4.5
	github.com/go-pg/pg v8.0.7+incompatible
	github.com/go-sql-driver/mysql v1.6.0
	github.com/h2non/filetype v1.1.3
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/klauspost/compress v1.16.7
	github.com/labstack/echo/v4 v4.10.2
	github.com/lib/pq v1.10.1
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/ory/dockertest/v3 v3.10.0
	github.com/praetorian-inc/fingerprintx v1.1.9
	github.com/projectdiscovery/dsl v0.0.26
	github.com/projectdiscovery/fasttemplate v0.0.2
	github.com/projectdiscovery/goflags v0.1.25
	github.com/projectdiscovery/gologger v1.1.11
	github.com/projectdiscovery/gostruct v0.0.1
	github.com/projectdiscovery/gozero v0.0.1
	github.com/projectdiscovery/httpx v1.3.5
	github.com/projectdiscovery/mapcidr v1.1.12
	github.com/projectdiscovery/n3iwf v0.0.0-20230523120440-b8cd232ff1f5
	github.com/projectdiscovery/ratelimit v0.0.12
	github.com/projectdiscovery/rdap v0.9.1-0.20221108103045-9865884d1917
	github.com/projectdiscovery/sarif v0.0.1
	github.com/projectdiscovery/tlsx v1.1.6-0.20231016194953-a3ff9518c766
	github.com/projectdiscovery/uncover v1.0.7
	github.com/projectdiscovery/utils v0.0.58
	github.com/projectdiscovery/wappalyzergo v0.0.109
	github.com/redis/go-redis/v9 v9.1.0
	github.com/ropnop/gokrb5/v8 v8.0.0-20201111231119-729746023c02
	github.com/sashabaranov/go-openai v1.15.3
	github.com/stretchr/testify v1.8.4
	github.com/zmap/zgrab2 v0.1.8-0.20230806160807-97ba87c0e706
	golang.org/x/term v0.13.0
	gopkg.in/src-d/go-git.v4 v4.13.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	aead.dev/minisign v0.2.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.3.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.0.0 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.14.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.8.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.5.0 // indirect
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cheggaaa/pb/v3 v3.1.4 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/cloudflare/cfssl v1.6.4 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/containerd/continuity v0.4.2 // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.10.0 // indirect
	github.com/docker/cli v24.0.5+incompatible // indirect
	github.com/docker/docker v24.0.5+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/free5gc/util v1.0.5-0.20230511064842-2e120956883b // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.9.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/go-github/v30 v30.1.0 // indirect
	github.com/google/pprof v0.0.0-20230821062121-407c9e7a662f // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.6 // indirect
	github.com/hbakhtiyor/strsim v0.0.0-20190107154042-4d2bbb273edf // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.0.0 // indirect
	github.com/jcmturner/rpc/v2 v2.0.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kataras/jwt v0.1.10 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mackerelio/go-osstat v0.2.4 // indirect
	github.com/minio/selfupdate v0.6.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.1.9 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/projectdiscovery/asnmap v1.0.5 // indirect
	github.com/projectdiscovery/cdncheck v1.0.9 // indirect
	github.com/projectdiscovery/freeport v0.0.5 // indirect
	github.com/quic-go/quic-go v0.38.1 // indirect
	github.com/refraction-networking/utls v1.5.4 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.1.1 // indirect
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/tidwall/btree v1.6.0 // indirect
	github.com/tidwall/buntdb v1.3.0 // indirect
	github.com/tidwall/gjson v1.16.0 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/tim-ywliu/nested-logrus-formatter v1.3.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/ysmood/fetchup v0.2.3 // indirect
	github.com/ysmood/got v0.34.1 // indirect
	github.com/yuin/goldmark v1.5.4 // indirect
	github.com/yuin/goldmark-emoji v1.0.1 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	golang.org/x/arch v0.3.0 // indirect
	gopkg.in/djherbis/times.v1 v1.3.0 // indirect
	mellium.im/sasl v0.3.1 // indirect
)

require (
	git.mills.io/prologic/smtpd v0.0.0-20210710122116-a525b76c287a // indirect
	github.com/Mzack9999/go-http-digest-auth-client v0.6.1-0.20220414142836-eb8883508809 // indirect
	github.com/Mzack9999/ldapserver v1.0.2-0.20211229000134-b44a0d6ad0dd // indirect
	github.com/PuerkitoBio/goquery v1.8.1 // indirect
	github.com/akrylysov/pogreb v0.10.1 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/xpath v1.2.3
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/caddyserver/certmagic v0.19.2 // indirect
	github.com/cnf/structhash v0.0.0-20201127153200-e1b16c1ebc08 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goburrow/cache v0.1.4 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.2 // indirect
	github.com/hdm/jarm-go v0.0.7 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/itchyny/timefmt-go v0.1.5 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/microcosm-cc/bluemonday v1.0.25 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/projectdiscovery/blackrock v0.0.1 // indirect
	github.com/projectdiscovery/networkpolicy v0.0.6
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/trivago/tgo v1.0.7
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/ulule/deepcopier v0.0.0-20200430083143-45decc6639b6 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	github.com/ysmood/goob v0.4.0 // indirect
	github.com/ysmood/gson v0.7.3 // indirect
	github.com/ysmood/leakless v0.8.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	github.com/zmap/rc2 v0.0.0-20190804163417-abaa70531248 // indirect
	github.com/zmap/zcrypto v0.0.0-20230829152017-3b5d61809233 // indirect
	go.etcd.io/bbolt v1.3.7 // indirect
	go.uber.org/zap v1.25.0 // indirect
	goftp.io/server/v2 v2.0.1 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	golang.org/x/mod v0.13.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.14.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6 // indirect
	gopkg.in/corvus-ch/zbase32.v1 v1.0.0 // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230518184743-7afd39499903 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/alecthomas/chroma v0.10.0
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.19.3 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/dop251/goja_nodejs v0.0.0-20230821135201-94e508132562
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.4.1 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/labstack/gommon v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/src-d/gcfg v1.4.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)
