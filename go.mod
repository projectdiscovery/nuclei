module github.com/projectdiscovery/nuclei/v3

go 1.24.2

toolchain go1.24.4

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/andygrunwald/go-jira v1.16.1
	github.com/antchfx/htmlquery v1.3.5
	github.com/bluele/gcache v0.0.2
	github.com/go-playground/validator/v10 v10.26.0
	github.com/go-rod/rod v0.116.2
	github.com/gobwas/ws v1.4.0
	github.com/google/go-github v17.0.0+incompatible
	github.com/invopop/jsonschema v0.13.0
	github.com/itchyny/gojq v0.12.17
	github.com/json-iterator/go v1.1.12
	github.com/julienschmidt/httprouter v1.3.0
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/miekg/dns v1.1.68
	github.com/olekukonko/tablewriter v1.0.8
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/clistats v0.1.1
	github.com/projectdiscovery/fastdialer v0.5.3
	github.com/projectdiscovery/hmap v0.0.99
	github.com/projectdiscovery/interactsh v1.2.4
	github.com/projectdiscovery/rawhttp v0.1.90
	github.com/projectdiscovery/retryabledns v1.0.112
	github.com/projectdiscovery/retryablehttp-go v1.3.4
	github.com/projectdiscovery/yamldoc-go v1.0.6
	github.com/remeh/sizedwaitgroup v1.0.0
	github.com/rs/xid v1.6.0
	github.com/segmentio/ksuid v1.0.4
	github.com/shirou/gopsutil/v3 v3.24.5 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/cast v1.9.2
	github.com/syndtr/goleveldb v1.0.0
	github.com/valyala/fasttemplate v1.2.2
	github.com/weppos/publicsuffix-go v0.50.1
	go.uber.org/multierr v1.11.0
	golang.org/x/net v0.48.0
	golang.org/x/oauth2 v0.30.0
	golang.org/x/text v0.32.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	carvel.dev/ytt v0.52.0
	code.gitea.io/sdk/gitea v0.17.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.10.1
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.1.0
	github.com/Azure/go-ntlmssp v0.1.0
	github.com/DataDog/gostackparse v0.7.0
	github.com/Masterminds/semver/v3 v3.2.1
	github.com/Mzack9999/gcache v0.0.0-20230410081825-519e28eab057
	github.com/Mzack9999/go-rsync v0.0.0-20250821180103-81ffa574ef4d
	github.com/Mzack9999/goja v0.0.0-20250507184235-e46100e9c697
	github.com/Mzack9999/goja_nodejs v0.0.0-20250507184139-66bcbf65c883
	github.com/alexsnet/go-vnc v0.1.0
	github.com/alitto/pond v1.9.2
	github.com/antchfx/xmlquery v1.4.4
	github.com/antchfx/xpath v1.3.5
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	github.com/aws/aws-sdk-go-v2 v1.36.5
	github.com/aws/aws-sdk-go-v2/config v1.29.17
	github.com/aws/aws-sdk-go-v2/credentials v1.17.70
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.82
	github.com/aws/aws-sdk-go-v2/service/s3 v1.82.0
	github.com/bytedance/sonic v1.14.0
	github.com/cespare/xxhash v1.1.0
	github.com/charmbracelet/glamour v0.10.0
	github.com/clbanning/mxj/v2 v2.7.0
	github.com/ditashi/jsbeautifier-go v0.0.0-20141206144643-2520a8026a9c
	github.com/docker/go-units v0.5.0
	github.com/fatih/structs v1.1.0
	github.com/getkin/kin-openapi v0.132.0
	github.com/go-git/go-git/v5 v5.16.2
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/go-pg/pg/v10 v10.15.0
	github.com/go-sql-driver/mysql v1.9.3
	github.com/goccy/go-json v0.10.5
	github.com/google/uuid v1.6.0
	github.com/h2non/filetype v1.1.3
	github.com/invopop/yaml v0.3.1
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/kitabisa/go-ci v1.0.3
	github.com/labstack/echo/v4 v4.13.4
	github.com/leslie-qiwa/flat v0.0.0-20230424180412-f9d1cf014baa
	github.com/lib/pq v1.10.9
	github.com/mattn/go-sqlite3 v1.14.28
	github.com/maypok86/otter/v2 v2.2.1
	github.com/mholt/archives v0.1.5
	github.com/microsoft/go-mssqldb v1.9.2
	github.com/ory/dockertest/v3 v3.12.0
	github.com/praetorian-inc/fingerprintx v1.1.15
	github.com/projectdiscovery/dsl v0.8.12
	github.com/projectdiscovery/fasttemplate v0.0.2
	github.com/projectdiscovery/gcache v0.0.0-20241015120333-12546c6e3f4c
	github.com/projectdiscovery/go-smb2 v0.0.0-20240129202741-052cc450c6cb
	github.com/projectdiscovery/goflags v0.1.74
	github.com/projectdiscovery/gologger v1.1.67
	github.com/projectdiscovery/gostruct v0.0.2
	github.com/projectdiscovery/gozero v0.1.1-0.20251027191944-a4ea43320b81
	github.com/projectdiscovery/httpx v1.7.4
	github.com/projectdiscovery/mapcidr v1.1.97
	github.com/projectdiscovery/n3iwf v0.0.0-20230523120440-b8cd232ff1f5
	github.com/projectdiscovery/networkpolicy v0.1.33
	github.com/projectdiscovery/ratelimit v0.0.83
	github.com/projectdiscovery/rdap v0.9.0
	github.com/projectdiscovery/sarif v0.0.1
	github.com/projectdiscovery/tlsx v1.2.2
	github.com/projectdiscovery/uncover v1.2.0
	github.com/projectdiscovery/useragent v0.0.106
	github.com/projectdiscovery/utils v0.8.0
	github.com/projectdiscovery/wappalyzergo v0.2.64
	github.com/redis/go-redis/v9 v9.11.0
	github.com/seh-msft/burpxml v1.0.1
	github.com/shurcooL/graphql v0.0.0-20230722043721-ed46e5a46466
	github.com/sijms/go-ora/v2 v2.9.0
	github.com/stretchr/testify v1.11.1
	github.com/tarunKoyalwar/goleak v0.0.0-20240429141123-0efa90dbdcf9
	github.com/testcontainers/testcontainers-go v0.38.0
	github.com/testcontainers/testcontainers-go/modules/mongodb v0.37.0
	github.com/yassinebenaid/godump v0.11.1
	github.com/zmap/zgrab2 v0.1.8
	gitlab.com/gitlab-org/api/client-go v0.130.1
	go.mongodb.org/mongo-driver v1.17.4
	golang.org/x/term v0.38.0
	gopkg.in/yaml.v3 v3.0.1
	moul.io/http2curl v1.0.0
)

require (
	aead.dev/minisign v0.2.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	git.mills.io/prologic/smtpd v0.0.0-20210710122116-a525b76c287a // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.18.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.1 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.4.2 // indirect
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Mzack9999/go-http-digest-auth-client v0.6.1-0.20220414142836-eb8883508809 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/PuerkitoBio/goquery v1.11.0 // indirect
	github.com/STARRY-S/zip v0.2.3 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/akrylysov/pogreb v0.10.2 // indirect
	github.com/alecthomas/chroma/v2 v2.14.0 // indirect
	github.com/alecthomas/kingpin/v2 v2.4.0 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.11 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.32 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.7.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.34.0 // indirect
	github.com/aws/smithy-go v1.22.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/bits-and-blooms/bitset v1.13.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.5.0 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.1 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/brianvoe/gofakeit/v7 v7.2.1 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/bytedance/sonic/loader v0.3.0 // indirect
	github.com/caddyserver/certmagic v0.19.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/censys/censys-sdk-go v0.19.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/lipgloss v1.1.1-0.20250404203927-76690c660834 // indirect
	github.com/charmbracelet/x/ansi v0.8.0 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13 // indirect
	github.com/charmbracelet/x/exp/slice v0.0.0-20250327172914-2fdc97757edf // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/cheggaaa/pb/v3 v3.1.6 // indirect
	github.com/cloudflare/cfssl v1.6.4 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/cloudwego/base64x v0.1.5 // indirect
	github.com/cnf/structhash v0.0.0-20250313080605-df4c6cc74a9a // indirect
	github.com/containerd/continuity v0.4.5 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/cyphar/filepath-securejoin v0.5.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/davidmz/go-pageant v1.0.2 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/djherbis/times v1.6.0 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/docker/cli v27.4.1+incompatible // indirect
	github.com/docker/docker v28.3.3+incompatible // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/ebitengine/purego v0.8.4 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/ericlagergren/decimal v0.0.0-20240411145413-00de7ca16731 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/felixge/fgprof v0.9.5 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/free5gc/util v1.0.5-0.20230511064842-2e120956883b // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/gaissmai/bart v0.26.0 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.9.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-fed/httpsig v1.1.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.2 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-pg/zerochecker v0.2.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/google/go-github/v30 v30.1.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/gosimple/slug v1.15.0 // indirect
	github.com/gosimple/unidecode v1.0.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hbakhtiyor/strsim v0.0.0-20190107154042-4d2bbb273edf // indirect
	github.com/hdm/jarm-go v0.0.7 // indirect
	github.com/iangcarroll/cookiemonster v1.6.0 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/itchyny/timefmt-go v0.1.6 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/k14s/starlark-go v0.0.0-20200720175618-3a5c849cc368 // indirect
	github.com/kaiakz/ubuffer v0.0.0-20200803053910-dd1083087166 // indirect
	github.com/kataras/jwt v0.1.10 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/logrusorgru/aurora/v4 v4.0.0 // indirect
	github.com/lor00x/goldap v0.0.0-20240304151906-8d785c64d1c8 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20250821153705-5981dea3221d // indirect
	github.com/mackerelio/go-osstat v0.2.4 // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.0.1 // indirect
	github.com/minio/selfupdate v0.6.1-0.20230907112617-f11e74f84ca7 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/go-archive v0.1.0 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/nwaples/rardecode/v2 v2.2.2 // indirect
	github.com/oasdiff/yaml v0.0.0-20250309154309-f31be36b4037 // indirect
	github.com/oasdiff/yaml3 v0.0.0-20250309153720-d2182401db90 // indirect
	github.com/olekukonko/errors v1.1.0 // indirect
	github.com/olekukonko/ll v0.0.9 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runc v1.2.8 // indirect
	github.com/openrdap/rdap v0.9.1 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.23 // indirect
	github.com/pjbgf/sha1cd v0.3.2 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/projectdiscovery/asnmap v1.1.1 // indirect
	github.com/projectdiscovery/blackrock v0.0.1 // indirect
	github.com/projectdiscovery/cdncheck v1.2.19 // indirect
	github.com/projectdiscovery/freeport v0.0.7 // indirect
	github.com/projectdiscovery/ldapserver v1.0.2-0.20240219154113-dcc758ebc0cb // indirect
	github.com/projectdiscovery/machineid v0.0.0-20250715113114-c77eb3567582 // indirect
	github.com/refraction-networking/utls v1.7.1 // indirect
	github.com/sashabaranov/go-openai v1.37.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/shirou/gopsutil/v4 v4.25.7 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/sorairolake/lzip-go v0.3.8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/tidwall/btree v1.7.0 // indirect
	github.com/tidwall/buntdb v1.3.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/tim-ywliu/nested-logrus-formatter v1.3.2 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/vmihailenco/bufpool v0.1.11 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.4 // indirect
	github.com/vmihailenco/tagparser v0.1.2 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/vulncheck-oss/go-exploit v1.51.0 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/ysmood/fetchup v0.2.3 // indirect
	github.com/ysmood/got v0.40.0 // indirect
	github.com/yuin/goldmark v1.7.13 // indirect
	github.com/yuin/goldmark-emoji v1.0.5 // indirect
	github.com/zcalusic/sysinfo v1.0.2 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.62.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	mellium.im/sasl v0.3.2 // indirect
)

require (
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/goburrow/cache v0.1.4 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/trivago/tgo v1.0.7
	github.com/ysmood/goob v0.4.0 // indirect
	github.com/ysmood/gson v0.7.3 // indirect
	github.com/ysmood/leakless v0.9.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zmap/rc2 v0.0.0-20190804163417-abaa70531248 // indirect
	github.com/zmap/zcrypto v0.0.0-20240512203510-0fef58d9a9db // indirect
	go.etcd.io/bbolt v1.4.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	goftp.io/server/v2 v2.0.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.39.0
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6 // indirect
	gopkg.in/corvus-ch/zbase32.v1 v1.0.0 // indirect
)

require (
	github.com/alecthomas/chroma v0.10.0
	github.com/go-echarts/go-echarts/v2 v2.6.0
	gopkg.in/warnings.v0 v0.1.2 // indirect
)

// https://go.dev/ref/mod#go-mod-file-retract
retract v3.2.0 // retract due to broken js protocol issue
