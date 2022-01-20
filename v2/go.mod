module github.com/projectdiscovery/nuclei/v2

go 1.17

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/alecthomas/jsonschema v0.0.0-20211022214203-8b29eab41725
	github.com/andygrunwald/go-jira v1.14.0
	github.com/antchfx/htmlquery v1.2.4
	github.com/apex/log v1.9.0
	github.com/blang/semver v3.5.1+incompatible
	github.com/bluele/gcache v0.0.2
	github.com/corpix/uarand v0.1.1
	github.com/go-playground/validator/v10 v10.10.0
	github.com/go-rod/rod v0.101.8
	github.com/gobwas/ws v1.1.0
	github.com/google/go-github v17.0.0+incompatible
	github.com/itchyny/gojq v0.12.6
	github.com/json-iterator/go v1.1.12
	github.com/julienschmidt/httprouter v1.3.0
	github.com/karlseguin/ccache v2.0.3+incompatible
	github.com/karrick/godirwalk v1.16.1
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/miekg/dns v1.1.45
	github.com/olekukonko/tablewriter v0.0.5
	github.com/owenrumney/go-sarif v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/clistats v0.0.8
	github.com/projectdiscovery/cryptoutil v0.0.0-20210805184155-b5d2512f9345
	github.com/projectdiscovery/fastdialer v0.0.14
	github.com/projectdiscovery/filekv v0.0.0-20210915124239-3467ef45dd08
	github.com/projectdiscovery/fileutil v0.0.0-20210928100737-cab279c5d4b5
	github.com/projectdiscovery/goflags v0.0.8-0.20211028121123-edf02bc05b1a
	github.com/projectdiscovery/gologger v1.1.4
	github.com/projectdiscovery/hmap v0.0.2-0.20210917080408-0fd7bd286bfa
	github.com/projectdiscovery/interactsh v0.0.8-0.20220112083504-b0b3b2f359a5
	github.com/projectdiscovery/nuclei-updatecheck-api v0.0.0-20211006155443-c0a8d610a4df
	github.com/projectdiscovery/rawhttp v0.0.7
	github.com/projectdiscovery/retryabledns v1.0.13-0.20211109182249-43d38df59660
	github.com/projectdiscovery/retryablehttp-go v1.0.2
	github.com/projectdiscovery/stringsutil v0.0.0-20210830151154-f567170afdd9
	github.com/projectdiscovery/yamldoc-go v1.0.3-0.20211126104922-00d2c6bb43b6
	github.com/remeh/sizedwaitgroup v1.0.0
	github.com/rs/xid v1.3.0 // indirect
	github.com/segmentio/ksuid v1.0.4
	github.com/shirou/gopsutil/v3 v3.21.12
	github.com/spaolacci/murmur3 v1.1.0
	github.com/spf13/cast v1.4.1
	github.com/syndtr/goleveldb v1.0.0
	github.com/tj/go-update v2.2.5-0.20200519121640-62b4b798fd68+incompatible
	github.com/valyala/fasttemplate v1.2.1
	github.com/weppos/publicsuffix-go v0.15.1-0.20210928183822-5ee35905bd95
	github.com/xanzy/go-gitlab v0.51.1
	github.com/ysmood/gson v0.6.4 // indirect
	github.com/ysmood/leakless v0.7.0 // indirect
	go.uber.org/atomic v1.9.0
	go.uber.org/multierr v1.7.0
	go.uber.org/ratelimit v0.2.0
	golang.org/x/net v0.0.0-20211216030914-fe4d6282115f
	golang.org/x/oauth2 v0.0.0-20211005180243-6b3c2da341f1
	golang.org/x/text v0.3.7
	gopkg.in/yaml.v2 v2.4.0
	moul.io/http2curl v1.0.0
)

require github.com/aws/aws-sdk-go v1.42.37

require github.com/projectdiscovery/folderutil v0.0.0-20211206150108-b4e7ea80f36e

require (
	github.com/Ice3man543/nvd v1.0.8
	github.com/openrdap/rdap v0.9.1-0.20191017185644-af93e7ef17b7
	github.com/projectdiscovery/iputil v0.0.0-20210804143329-3a30fcde43f3
	github.com/stretchr/testify v1.7.0
)

require (
	git.mills.io/prologic/smtpd v0.0.0-20210710122116-a525b76c287a // indirect
	github.com/Mzack9999/ldapserver v1.0.2-0.20211229000134-b44a0d6ad0dd // indirect
	github.com/PuerkitoBio/goquery v1.6.0 // indirect
	github.com/akrylysov/pogreb v0.10.1 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129 // indirect
	github.com/andybalholm/cascadia v1.1.0 // indirect
	github.com/antchfx/xpath v1.2.0 // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.0.1 // indirect
	github.com/c4milo/unpackit v0.1.0 // indirect
	github.com/caddyserver/certmagic v0.15.2 // indirect
	github.com/cnf/structhash v0.0.0-20201127153200-e1b16c1ebc08 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/goburrow/cache v0.1.4 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang-jwt/jwt v3.2.1+incompatible // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gosuri/uilive v0.0.4 // indirect
	github.com/gosuri/uiprogress v0.0.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.8 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/itchyny/timefmt-go v0.1.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mholt/acmez v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/projectdiscovery/blackrock v0.0.0-20210415162320-b38689ae3a2e // indirect
	github.com/projectdiscovery/mapcidr v0.0.8 // indirect
	github.com/projectdiscovery/networkpolicy v0.0.1 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	github.com/tklauser/numcpus v0.3.0 // indirect
	github.com/trivago/tgo v1.0.7 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	github.com/ysmood/goob v0.3.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	github.com/zclconf/go-cty v1.10.0 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.uber.org/zap v1.20.0 // indirect
	goftp.io/server/v2 v2.0.0 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/sys v0.0.0-20211210111614-af8b64212486 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.1.6-0.20210726203631-07bc1bf47fb2 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6 // indirect
	gopkg.in/corvus-ch/zbase32.v1 v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
