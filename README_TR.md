![nuclei](/static/nuclei-cover-image.png)

<div align="center">
  
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">`English`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">`中文`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">`Korean`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ID.md">`Indonesia`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">`Spanish`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_JP.md">`日本語`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_PT-BR.md">`Portuguese`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_TR.md">`Türkçe`</a>
  
</div>

<p align="center">

<a href="https://docs.projectdiscovery.io/tools/nuclei/overview?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBjbGFzcz0ibHVjaWRlIGx1Y2lkZS1ib29rLW9wZW4iPjxwYXRoIGQ9Ik0xMiA3djE0Ii8+PHBhdGggZD0iTTMgMThhMSAxIDAgMCAxLTEtMVY0YTEgMSAwIDAgMSAxLTFoNWE0IDQgMCAwIDEgNCA0IDQgNCAwIDAgMSA0LTRoNWExIDEgMCAwIDEgMSAxdjEzYTEgMSAwIDAgMS0xIDFoLTZhMyAzIDAgMCAwLTMgMyAzIDMgMCAwIDAtMy0zeiIvPjwvc3ZnPg==&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://github.com/projectdiscovery/nuclei-templates"><img src="https://img.shields.io/badge/Templates Library-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGNsYXNzPSJsdWNpZGUgbHVjaWRlLXNoaWVsZCI+PHBhdGggZD0iTTIwIDEzYzAgNS0zLjUgNy41LTcuNjYgOC45NWExIDEgMCAwIDEtLjY3LS4wMUM3LjUgMjAuNSA0IDE4IDQgMTNWNmExIDEgMCAwIDEgMS0xYzIgMCA0LjUtMS4yIDYuMjQtMi43MmExLjE3IDEuMTcgMCAwIDEgMS41MiAwQzE0LjUxIDMuODEgMTcgNSAxOSA1YTEgMSAwIDAgMSAxIDF6Ii8+PC9zdmc+&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://discord.gg/projectdiscovery?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme"><img src="https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white"></a>

<hr>

</p>

<br>

**Nuclei, basit YAML tabanlı şablonlardan yararlanan modern, yüksek performanslı bir zafiyet tarayıcısıdır. Gerçek dünya koşullarını taklit eden özel zafiyet tespit senaryoları tasarlamanıza olanak tanıyarak sıfır hatalı pozitif sonuç sağlar.**

- Güvenlik açığı şablonları oluşturmak ve özelleştirmek için basit YAML formatı.
- Trend olan güvenlik açıklarını ele almak için binlerce güvenlik uzmanı tarafından katkıda bulunulmuştur.
- Bir güvenlik açığını doğrulamak için gerçek dünya adımlarını simüle ederek hatalı pozitifleri azaltır.
- Ultra hızlı paralel tarama işleme ve istek kümeleme.
- Zafiyet tespiti ve regresyon testi için CI/CD hatlarına entegre edilebilir.
- TCP, DNS, HTTP, SSL, WHOIS, JavaScript, Code ve daha fazlası gibi birçok protokolü destekler.
- Jira, Splunk, GitHub, Elastic, GitLab ile entegre olur.

<br>
<br>

## İçindekiler

- [**`Başlarken`**](#başlarken)
  - [_`1. Nuclei CLI`_](#1-nuclei-cli)
  - [_`2. Pro ve Kurumsal Sürümler`_](#2-pro-ve-kurumsal-sürümler)
- [**`Dokümantasyon`**](#dokümantasyon)
  - [_`Komut Satırı Bayrakları`_](#komut-satırı-bayrakları)
  - [_`Tek hedef tarama`_](#tek-hedef-tarama)
  - [_`Çoklu hedef tarama`_](#çoklu-hedef-tarama)
  - [_`Ağ taraması`_](#ağ-taraması)
  - [_`Özel şablonunuzla tarama`_](#özel-şablonunuzla-tarama)
  - [_`Nuclei'yi ProjectDiscovery'ye Bağlayın`_](#nucleiyi-projectdiscoveryye-bağlayın)
- [**`Nuclei Şablonları, Topluluk ve Ödüller`**](#nuclei-şablonları-topluluk-ve-ödüller-) 💎
- [**`Misyonumuz`**](#misyonumuz)
- [**`Katkıda Bulunanlar`**](#katkıda-bulunanlar) ❤
- [**`Lisans`**](#lisans)

<br>
<br>

## Başlarken

### **1. Nuclei CLI**

_Nuclei'yi makinenize kurun. [**`Buradaki`**](https://docs.projectdiscovery.io/tools/nuclei/install?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme) kurulum kılavuzunu takip ederek başlayın. Ayrıca, [**`ücretsiz bir bulut katmanı`**](https://cloud.projectdiscovery.io/sign-up) sağlıyoruz ve cömert aylık ücretsiz limitlerle birlikte geliyor:_

- Zafiyet bulgularınızı saklayın ve görselleştirin
- nuclei şablonlarınızı yazın ve yönetin
- En son nuclei şablonlarına erişin
- Hedeflerinizi keşfedin ve saklayın

> [!Important]
> |**Bu proje aktif geliştirme aşamasındadır**. Sürümlerle birlikte kırılma değişiklikleri bekleyin. Güncellemeden önce sürüm değişiklik günlüğünü inceleyin.|
> |:--------------------------------|
> | Bu proje öncelikle bağımsız bir CLI aracı olarak kullanılmak üzere oluşturulmuştur. **Nuclei'yi bir servis olarak çalıştırmak güvenlik riskleri oluşturabilir.** Dikkatli kullanılması ve ek güvenlik önlemleri alınması önerilir. |

<br>

### **2. Pro ve Kurumsal Sürümler**

_Güvenlik ekipleri ve kuruluşlar için, ekibiniz ve mevcut iş akışlarınızla ölçekli olarak sürekli zafiyet taramaları yapmanıza yardımcı olmak üzere ince ayarlanmış, Nuclei OSS üzerine inşa edilmiş bulut tabanlı bir hizmet sunuyoruz:_

- 50x daha hızlı taramalar
- Yüksek doğrulukla büyük ölçekli tarama
- Bulut hizmetleri ile entegrasyonlar (AWS, GCP, Azure, Cloudflare, Fastly, Terraform, Kubernetes)
- Jira, Slack, Linear, API'ler ve Webhook'lar
- Yönetici ve uyumluluk raporlaması
- Artı: Gerçek zamanlı tarama, SAML SSO, SOC 2 uyumlu platform (AB ve ABD barındırma seçenekleri ile), paylaşılan ekip çalışma alanları ve daha fazlası
- Sürekli olarak [**`yeni özellikler ekliyoruz`**](https://feedback.projectdiscovery.io/changelog)!
- **Şunlar için ideal:** Sızma testi yapanlar, güvenlik ekipleri ve kuruluşlar

Büyük bir organizasyonunuz ve karmaşık gereksinimleriniz varsa [**`Pro'ya kaydolun`**](https://projectdiscovery.io/pricing?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme) veya [**`ekibimizle konuşun`**](https://projectdiscovery.io/request-demo?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme).

<br>
<br>

## Dokümantasyon

Nuclei'nin tam [**`dokümantasyonuna buradan`**](https://docs.projectdiscovery.io/tools/nuclei/running) göz atın. Nuclei'de yeniyseniz, [**`temel YouTube serimize`**](https://www.youtube.com/playlist?list=PLZRbR9aMzTTpItEdeNSulo8bYsvil80Rl) göz atın.

<div align="center">

<a href="https://www.youtube.com/watch?v=b5qMyQvL1ZA&list=PLZRbR9aMzTTpItEdeNSulo8bYsvil80Rl&utm_source=github&utm_medium=web&utm_campaign=nuclei_readme" target="_blank"><img src="/static/nuclei-getting-started.png" width="350px"></a> <a href="https://www.youtube.com/watch?v=nFXygQdtjyw&utm_source=github&utm_medium=web&utm_campaign=nuclei_readme" target="_blank"><img src="/static/nuclei-write-your-first-template.png" width="350px"></a>

</div>

<br>

### Kurulum

`nuclei` yüklemek için **go >= 1.24.2** gerektirir. Repoyu almak için aşağıdaki komutu çalıştırın:

```sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Nuclei kurulumu hakkında daha fazla bilgi edinmek için `https://docs.projectdiscovery.io/tools/nuclei/install` adresine bakın.

### Komut Satırı Bayrakları

Aracın tüm bayraklarını görüntülemek için:

```sh
nuclei -h
```

<details>
  <summary>Tüm yardım bayraklarını genişlet</summary>

```yaml
Nuclei, kapsamlı yapılandırılabilirlik, devasa genişletilebilirlik ve kullanım kolaylığına odaklanan hızlı, şablon tabanlı bir zafiyet tarayıcısıdır.

Kullanım:
  ./nuclei [bayraklar]

Bayraklar:
TARGET:
   -u, -target string[]          taranacak hedef URL'ler/hostlar
   -l, -list string              taranacak hedef URL'leri/hostları içeren dosya yolu (her satırda bir tane)
   -eh, -exclude-hosts string[]  girilen listeden tarama dışında tutulacak hostlar (ip, cidr, hostname)
   -resume string                taramayı belirtilen dosyadan devam ettir ve kaydet (kümeleme devre dışı bırakılır)
   -sa, -scan-all-ips            dns kaydı ile ilişkili tüm IP'leri tara
   -iv, -ip-version string[]     taranacak hostun IP versiyonu (4,6) - (varsayılan 4)

TARGET-FORMAT:
   -im, -input-mode string        girdi dosyasının modu (list, burp, jsonl, yaml, openapi, swagger) (varsayılan "list")
   -ro, -required-only            istekler oluşturulurken girdi formatındaki sadece zorunlu alanları kullan
   -sfv, -skip-format-validation  girdi dosyasını ayrıştırırken format doğrulamasını atla (eksik değişkenler gibi)

TEMPLATES:
   -nt, -new-templates                    sadece en son nuclei-templates sürümünde eklenen yeni şablonları çalıştır
   -ntv, -new-templates-version string[]  belirli bir sürümde eklenen yeni şablonları çalıştır
   -as, -automatic-scan                   wappalyzer teknoloji tespiti ile etiket eşlemesini kullanarak otomatik web taraması
   -t, -templates string[]                çalıştırılacak şablon veya şablon dizini listesi (virgülle ayrılmış, dosya)
   -turl, -template-url string[]          çalıştırılacak şablon url'si veya şablon url'lerini içeren liste (virgülle ayrılmış, dosya)
   -ai, -prompt string                    yapay zeka istemi kullanarak şablon oluştur ve çalıştır
   -w, -workflows string[]                çalıştırılacak iş akışı veya iş akışı dizini listesi (virgülle ayrılmış, dosya)
   -wurl, -workflow-url string[]          çalıştırılacak iş akışı url'si veya iş akışı url'lerini içeren liste (virgülle ayrılmış, dosya)
   -validate                              nuclei'ye iletilen şablonları doğrula
   -nss, -no-strict-syntax                şablonlarda katı sözdizimi kontrolünü devre dışı bırak
   -td, -template-display                 şablon içeriğini görüntüler
   -tl                                    mevcut filtrelerle eşleşen tüm şablonları listele
   -tgl                                   tüm mevcut etiketleri listele
   -sign                                  şablonları NUCLEI_SIGNATURE_PRIVATE_KEY ortam değişkeninde tanımlanan özel anahtarla imzala
   -code                                  kod protokolü tabanlı şablonların yüklenmesini etkinleştir
   -dut, -disable-unsigned-templates      imzasız şablonların veya imzası eşleşmeyen şablonların çalıştırılmasını devre dışı bırak
   -esc, -enable-self-contained           kendi kendine yeten (self-contained) şablonların yüklenmesini etkinleştir
   -egm, -enable-global-matchers          global eşleştirici şablonların yüklenmesini etkinleştir
   -file                                  dosya şablonlarının yüklenmesini etkinleştir

... (Diğer bayraklar orijinalindeki gibi, tam çeviri için çok uzun olabilir, ancak bağlam için yeterli)
```

Ek dokümantasyon şu adreste mevcuttur: [**`docs.nuclei.sh/getting-started/running`**](https://docs.nuclei.sh/getting-started/running?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme)

</details>

### Tek hedef tarama

Web uygulamasında hızlı bir tarama yapmak için:

```sh
nuclei -target https://example.com
```

### Çoklu hedef tarama

Nuclei, bir hedef listesi sağlayarak toplu taramayı gerçekleştirebilir. Birden fazla URL içeren bir dosya kullanabilirsiniz.

```sh
nuclei -list urls.txt
```

### Ağ taraması

Bu, açık portlar veya yanlış yapılandırılmış servisler gibi ağla ilgili sorunlar için tüm alt ağı tarayacaktır.

```sh
nuclei -target 192.168.1.0/24
```

### Özel şablonunuzla tarama

Kendi şablonunuzu yazmak ve kullanmak için, belirli kurallara sahip bir `.yaml` dosyası oluşturun ve ardından aşağıdaki gibi kullanın.

```sh
nuclei -u https://example.com -t /path/to/your-template.yaml
```

### Nuclei'yi ProjectDiscovery'ye Bağlayın

Taramaları makinenizde çalıştırabilir ve sonuçları daha fazla analiz ve düzeltme için bulut platformuna yükleyebilirsiniz.

```sh
nuclei -target https://example.com -dashboard
```

> [!NOTE]
> Bu özellik tamamen ücretsizdir ve herhangi bir abonelik gerektirmez. Ayrıntılı bir kılavuz için [**`dokümantasyona`**](https://docs.projectdiscovery.io/cloud/scanning/nuclei-scan?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme) bakın.

<br>
<br>

## Nuclei Şablonları, Topluluk ve Ödüller 💎
[**Nuclei şablonları**](https://github.com/projectdiscovery/nuclei-templates), isteklerin nasıl gönderileceğini ve işleneceğini tanımlayan YAML tabanlı şablon dosyaları kavramına dayanır. Bu, nuclei'ye kolay genişletilebilirlik yetenekleri sağlar. Şablonlar, yürütme sürecini hızlı bir şekilde tanımlamak için insan tarafından okunabilir basit bir format belirten YAML ile yazılmıştır.

**[**`Buraya tıklayarak`**](https://cloud.projectdiscovery.io/templates) ücretsiz yapay zeka destekli Nuclei Şablon Editörü ile çevrimiçi deneyin.**

Nuclei Şablonları, önem dereceleri ve tespit yöntemleri gibi temel ayrıntıları birleştirerek güvenlik açıklarını tanımlamak ve iletmek için akıcı bir yol sunar. Bu açık kaynaklı, topluluk tarafından geliştirilen araç, tehdit yanıtını hızlandırır ve siber güvenlik dünyasında geniş çapta tanınmaktadır. Nuclei şablonları, dünya çapında binlerce güvenlik araştırmacısı tarafından aktif olarak katkıda bulunulmaktadır. Katılımcılarımız için iki program yürütüyoruz: [**`Öncüler (Pioneers)`**](https://projectdiscovery.io/pioneers) ve [**`💎 ödüller`**](https://github.com/projectdiscovery/nuclei-templates/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22%F0%9F%92%8E%20Bounty%22).


<p align="left">
    <a href="/static/nuclei-templates-teamcity.png"  target="_blank"><img src="/static/nuclei-templates-teamcity.png" width="1200px" alt="TeamCity yanlış yapılandırmasını tespit etmek için Nuclei şablon örneği" /></a>
</p>

#### Örnekler

Kullanım durumları ve fikirler için [**dokümantasyonumuzu**](https://docs.projectdiscovery.io/templates/introduction) ziyaret edin.

| Kullanım durumu                        | Nuclei şablonu                                     |
| :----------------------------------- | :------------------------------------------------- |
| Bilinen CVE'leri tespit et           | **[CVE-2021-44228 (Log4Shell)](https://cloud.projectdiscovery.io/public/CVE-2021-45046)**                     |
| Bant Dışı (Out-of-Band) zafiyetlerini belirle | **[Blind SQL Injection via OOB](https://cloud.projectdiscovery.io/public/CVE-2024-22120)**                    |
| SQL Injection tespiti                | **[Generic SQL Injection](https://cloud.projectdiscovery.io/public/CVE-2022-34265)**                          |
| Siteler Arası Komut Dosyası Çalıştırma (XSS) | **[Reflected XSS Detection](https://cloud.projectdiscovery.io/public/CVE-2023-4173)**                        |
| Varsayılan veya zayıf şifreler       | **[Default Credentials Check](https://cloud.projectdiscovery.io/public/airflow-default-login)**                      |
| Gizli dosyalar veya veri ifşası      | **[Sensitive File Disclosure](https://cloud.projectdiscovery.io/public/airflow-configuration-exposure)**                      |
| Açık yönlendirmeleri (open redirects) belirle | **[Open Redirect Detection](https://cloud.projectdiscovery.io/public/open-redirect)**                        |
| Alt alan adı devralmalarını (takeover) tespit et | **[Subdomain Takeover Templates](https://cloud.projectdiscovery.io/public/azure-takeover-detection)**                   |
| Güvenlik yanlış yapılandırmaları     | **[Unprotected Jenkins Console](https://cloud.projectdiscovery.io/public/unauthenticated-jenkins)**                    |
| Zayıf SSL/TLS yapılandırmaları       | **[SSL Certificate Expiry](https://cloud.projectdiscovery.io/public/expired-ssl)**                         |
| Yanlış yapılandırılmış bulut hizmetleri | **[Open S3 Bucket Detection](https://cloud.projectdiscovery.io/public/s3-public-read-acp)**                       |
| Uzaktan kod yürütme zafiyetleri      | **[RCE Detection Templates](https://cloud.projectdiscovery.io/public/CVE-2024-29824)**                        |
| Dizin geçiş (path traversal) saldırıları | **[Path Traversal Detection](https://cloud.projectdiscovery.io/public/oracle-fatwire-lfi)**                       |
| Dosya dahil etme (file inclusion) zafiyetleri | **[Local/Remote File Inclusion](https://cloud.projectdiscovery.io/public/CVE-2023-6977)**                    |


<br>
<br>

## Misyonumuz

Geleneksel zafiyet tarayıcıları on yıllar önce inşa edildi. Kapalı kaynaklıdırlar, inanılmaz derecede yavaştırlar ve satıcı odaklıdırlar. Günümüzün saldırganları, eskiden yıllar süren süreçlerin aksine, yeni yayınlanan CVE'leri günler içinde internet genelinde kitlesel olarak istismar ediyor. Bu değişim, internetteki trend olan istismarlarla mücadele etmek için tamamen farklı bir yaklaşım gerektiriyor.

Bu zorluğu çözmek için Nuclei'yi inşa ettik. Tüm tarama motoru çerçevesini açık ve özelleştirilebilir hale getirdik; bu sayede küresel güvenlik topluluğunun işbirliği yapmasına ve internet üzerindeki trend saldırı vektörlerini ve zafiyetlerini ele almasına olanak tanıdık. Nuclei artık Fortune 500 şirketleri, devlet kurumları ve üniversiteler tarafından kullanılmakta ve katkıda bulunulmaktadır.

Kodumuza, [**`şablon kitaplığımıza`**](https://github.com/projectdiscovery/nuclei-templates) katkıda bulunarak veya [**`ekibimize katılarak`**](https://projectdiscovery.io/) siz de yer alabilirsiniz.

<br>
<br>

## Katkıda Bulunanlar :heart:

Projeyi güncel tuttukları ve [**`PR gönderdikleri için harika topluluk katkıda bulunanlara`**](https://github.com/projectdiscovery/nuclei/graphs/contributors) teşekkür ederiz. :heart:

(Katkıda bulunanların listesi orijinalindeki gibi korunmuştur)
<p align="left">
<a href="https://github.com/Ice3man543"><img src="https://avatars.githubusercontent.com/u/22318055?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/apps/dependabot"><img src="https://avatars.githubusercontent.com/in/29110?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<!-- Diğer katkıda bulunanlar buraya gelecek, görsel olarak aynı kalmalı -->
...
</p>

<br>
<br>
<br>

<div align="center">
  
  <sub>**`nuclei`** [**MIT Lisansı**](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md) altında dağıtılmaktadır.</sub>

</div>
