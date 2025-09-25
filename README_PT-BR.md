<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">Scanner de vulnerabilidades rápido e personalizável baseado em uma DSL simples baseada em YAML.</h4>


<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/downloads/projectdiscovery/nuclei/total">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases/"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/github/issues-raw/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/discussions"><img src="https://img.shields.io/github/discussions/projectdiscovery/nuclei">
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
</p>

<p align="center">
  <a href="#como-funciona">Como funciona</a> •
  <a href="#instalacao-do-nuclei">Instalação</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/">Documentação</a> •
  <a href="#créditos">Créditos</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/faq">Perguntas Frequentes</a> •
  <a href="https://discord.gg/projectdiscovery">Junte-se ao Discord</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">English</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">中文</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">Korean</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ID.md">Indonesia</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">Spanish</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_PT-BR.md">Portuguese</a>
</p>

---

O Nuclei é utilizado para enviar solicitações para vários alvos baseados em um modelo, resultando em zero falsos positivos e proporcionando uma varredura rápida em um grande número de hosts. O Nuclei oferece suporte a uma variedade de protocolos, incluindo TCP, DNS, HTTP, SSL, Arquivo, Whois, Websocket, Headless, Código, entre outros. Com modelos poderosos e flexíveis, o Nuclei pode ser usado para modelar todos os tipos de verificações de segurança.

Temos um [repositório dedicado](https://github.com/projectdiscovery/nuclei-templates) que abriga vários tipos de modelos de vulnerabilidades, contribuídos por **mais de 300** pesquisadores e engenheiros de segurança.

## Como funciona


<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>


| :exclamation:  **Aviso**  |
|---------------------------------|
| **Este projeto está em desenvolvimento ativo**. Alterações significativas são esperadas em versões futuras. Consulte o changelog antes de atualizar. |
| Este projeto foi desenvolvido principalmente para ser usado como uma ferramenta CLI independente. **Executar o Nuclei como um serviço pode implicar riscos de segurança.** É recomendável utilizá-lo com precaução e medidas de segurança adicionais. |

# Instalação do Nuclei

O Nuclei requer **go1.22** para ser instalado corretamente. Execute o seguinte comando para instalar a versão mais recente:

```sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

<details>
  <summary>Brew</summary>
  
  ```sh
  brew install nuclei
  ```
  
</details>
<details>
  <summary>Docker</summary>
  
  ```sh
  docker pull projectdiscovery/nuclei:latest
  ```
  
</details>

**Mais métodos de instalação [podem ser encontrados aqui](https://docs.projectdiscovery.io/tools/nuclei/install).**

<table>
<tr>
<td>  

### Modelos do Nuclei

O Nuclei possui suporte integrado para download/atualização automática de modelos a partir da versão [v2.5.2](https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2). O projeto [**Nuclei-Templates**](https://github.com/projectdiscovery/nuclei-templates) fornece uma lista de modelos prontos para uso, atualizados constantemente pela comunidade.

Você também pode usar a flag `update-templates` para atualizar os modelos do Nuclei a qualquer momento; também pode criar seus próprios testes para seu fluxo de trabalho e necessidades específicas seguindo o [guia de modelos](https://docs.projectdiscovery.io/templates/) do Nuclei.

A referência de sintaxe YAML DSL está disponível [aqui](SYNTAX-REFERENCE.md).

</td>
</tr>
</table>

### Uso

```sh
nuclei -h
```

Isso mostrará ajuda sobre a ferramenta. Aqui estão todas as opções que ela suporta.


```console
Nuclei é um scanner de vulnerabilidades rápido e baseado em templates  
que se concentra em sua ampla configurabilidade, extensibilidade e facilidade de uso.

Usage:
  ./nuclei [flags]

Flags:
TARGET:
   -u, -target string[]          URLs/hosts a serem escaneados
   -l, -list string              caminho do arquivo contendo a lista de URLs/hosts a serem escaneados (um por linha)
   -eh, -exclude-hosts string[]  hosts a serem excluídos do escaneamento na lista de entrada (ip, cidr, hostname)
   -resume string                retomar o escaneamento usando resume.cfg (a clusterização será desabilitada)
   -sa, -scan-all-ips            escanear todos os IPs associados ao registro DNS
   -iv, -ip-version string[]     versão de IP a escanear do nome do host (4,6) - (padrão 4)

TARGET-FORMAT:
   -im, -input-mode string        modo do arquivo de entrada (list, burp, jsonl, yaml, openapi, swagger) (padrão "list")
   -ro, -required-only            usar apenas campos obrigatórios no formato de entrada ao gerar requisições
   -sfv, -skip-format-validation  pular a validação de formato (como variáveis ausentes) ao processar o arquivo de entrada

TEMPLATES:
   -nt, -new-templates                    executar apenas os novos templates adicionados na última versão de nuclei-templates
   -ntv, -new-templates-version string[]  executar os novos templates adicionados na versão especificada
   -as, -automatic-scan                   escaneamento da web automático utilizando a detecção de tecnologia do Wappalyzer para mapeamento de tags
   -t, -templates string[]                lista de templates ou diretório de templates a executar (separados por vírgulas, arquivo)
   -turl, -template-url string[]          URL de template ou lista contendo URLs de templates a executar (separados por vírgulas, arquivo)
   -w, -workflows string[]                lista de fluxos de trabalho ou diretório de fluxos de trabalho a executar (separados por vírgulas, arquivo)
   -wurl, -workflow-url string[]          URL de fluxo de trabalho ou lista contendo URLs de fluxos de trabalho para executar (separados por vírgulas, arquivo)
   -validate                              valida os templates passados para o nuclei
   -nss, -no-strict-syntax                desativa a verificação de sintaxe estrita nos templates
   -td, -template-display                 exibe o conteúdo dos templates
   -tl                                    lista todos os templates disponíveis
   -tgl                                   lista todas as tags disponíveis
   -sign                                  assina os templates com a chave privada definida na variável de ambiente NUCLEI_SIGNATURE_PRIVATE_KEY
   -code                                  habilita o carregamento de templates baseados em protocolos de código
   -dut, -disable-unsigned-templates      desativa a execução de templates não assinados ou com assinatura incompatível

FILTERING:
   -a, -author string[]               templates a serem executados com base nos autores (separados por vírgulas, arquivo)
   -tags string[]                     templates a serem executados com base em tags (separados por vírgulas, arquivo)
   -etags, -exclude-tags string[]     templates a excluir com base em tags (separados por vírgulas, arquivo)
   -itags, -include-tags string[]     tags a executar mesmo que estejam excluídas por padrão ou configuração
   -id, -template-id string[]         templates a serem executados com base em IDs de template (separados por vírgulas, arquivo, permitem curingas)
   -eid, -exclude-id string[]         templates a excluir com base em IDs de template (separados por vírgulas, arquivo)
   -it, -include-templates string[]   caminho do arquivo de template ou diretório a executar mesmo que estejam excluídos por padrão ou configuração
   -et, -exclude-templates string[]   caminho do arquivo de template ou diretório a excluir (separados por vírgulas, arquivo)
   -em, -exclude-matchers string[]    matchers de template a excluir no resultado
   -s, -severity value[]              templates a executar com base na criticidade. Valores possíveis: info, baixo, médio, alto, crítico, desconhecido
   -es, -exclude-severity value[]     templates a excluir com base na criticidade. Valores possíveis: info, baixo, médio, alto, crítico, desconhecido
   -pt, -type value[]                 templates a executar com base no tipo de protocolo. Valores possíveis: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        templates a excluir com base no tipo de protocolo. Valores possíveis: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  templates a executar com base em condição de expressão

OUTPUT:
   -o, -output string            arquivo de saída para salvar as ocorrências/vulnerabilidades detectadas
   -sresp, -store-resp           armazenar todas as solicitações/respostas enviadas pelo nuclei no diretório de saída
   -srd, -store-resp-dir string  armazenar todas as solicitações/respostas enviadas pelo nuclei em um diretório personalizado (padrão "output")
   -silent                       exibir apenas os resultados
   -nc, -no-color                desativar a coloração do conteúdo de saída (códigos de escape ANSI)
   -j, -jsonl                    salvar a saída no formato JSONL(ines)
   -irr, -include-rr -omit-raw   incluir pares solicitação/resposta nas saídas JSON, JSONL e Markdown (apenas para achados) [OBSOLETO usar -omit-raw] (padrão true)
   -or, -omit-raw                omitir os pares solicitação/resposta nas saídas JSON, JSONL e Markdown (apenas para achados)
   -ot, -omit-template           omitir o template codificado na saída JSON, JSONL
   -nm, -no-meta                 desativar a exibição de metadados dos resultados na saída CLI
   -ts, -timestamp               ativar a exibição do carimbo de data/hora na saída CLI
   -rdb, -report-db string       banco de dados de relatórios do nuclei (usar sempre para persistir os dados dos relatórios)
   -ms, -matcher-status          exibir o estado de falha de correspondência
   -me, -markdown-export string  diretório para exportar resultados no formato Markdown
   -se, -sarif-export string     arquivo para exportar resultados no formato SARIF
   -je, -json-export string      arquivo para exportar resultados no formato JSON
   -jle, -jsonl-export string    arquivo para exportar resultados no formato JSONL(ines)

CONFIGURATIONS:
   -config string                        caminho do arquivo de configuração do nuclei
   -fr, -follow-redirects                ativar o acompanhamento de redirecionamentos para templates HTTP
   -fhr, -follow-host-redirects          seguir redirecionamentos no mesmo host
   -mr, -max-redirects int               número máximo de redirecionamentos a seguir para templates HTTP (padrão 10)
   -dr, -disable-redirects               desativar redirecionamentos para templates HTTP
   -rc, -report-config string            arquivo de configuração do módulo de relatórios do nuclei
   -H, -header string[]                  cabeçalho/cookie personalizado a incluir em todas as solicitações HTTP no formato header:value (CLI, arquivo)
   -V, -var value                        variáveis personalizadas no formato key=value
   -r, -resolvers string                 arquivo contendo uma lista de resolvers para o nuclei
   -sr, -system-resolvers                usar resolução DNS do sistema como fallback em caso de erro
   -dc, -disable-clustering              desativar o agrupamento de solicitações
   -passive                              ativar o modo de processamento passivo de respostas HTTP
   -fh2, -force-http2                    forçar conexões HTTP2 nas solicitações
   -ev, -env-vars                        ativar o uso de variáveis de ambiente no template
   -cc, -client-cert string              arquivo de certificado de cliente (codificado em PEM) usado para autenticar-se contra os hosts escaneados
   -ck, -client-key string               arquivo de chave de cliente (codificado em PEM) usado para autenticar-se contra os hosts escaneados
   -ca, -client-ca string                arquivo de autoridade de certificação de cliente (codificado em PEM) usado para autenticar-se contra os hosts escaneados
   -sml, -show-match-line                exibir linhas de correspondência para templates de arquivo, funciona apenas com extratores
   -ztls                                 usar a biblioteca ztls com fallback automático para padrão no tls13 [OBSOLETO] fallback automático para ztls já está ativado por padrão
   -sni string                           nome de host tls sni a ser usado (padrão: nome de domínio de entrada)
   -dt, -dialer-timeout value            tempo limite para solicitações de rede
   -dka, -dialer-keep-alive value        duração do keep-alive para solicitações de rede
   -lfa, -allow-local-file-access        permitir acesso a arquivos (payload) em qualquer lugar do sistema
   -lna, -restrict-local-network-access  bloquear conexões à rede local/privada
   -i, -interface string                 interface de rede a ser usada para o escaneamento de rede
   -at, -attack-type string              tipo de combinações de payload a realizar (batteringram, pitchfork, clusterbomb)
   -sip, -source-ip string               endereço IP de origem a ser usado para o escaneamento de rede
   -rsr, -response-size-read int         tamanho máximo de resposta a ser lido em bytes (padrão 10485760)
   -rss, -response-size-save int         tamanho máximo de resposta a ser salvo em bytes (padrão 1048576)
   -reset                                remove todos os arquivos de configuração e dados do nuclei (incluindo os nuclei-templates)
   -tlsi, -tls-impersonate               ativar randomização experimental do client hello (ja3) tls

INTERACTSH:
   -iserver, -interactsh-server string  URL do servidor interactsh para instância auto-hospedada (padrão: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    token de autenticação para o servidor interactsh auto-hospedado
   -interactions-cache-size int         número de solicitações a serem mantidas no cache de interações (padrão 5000)
   -interactions-eviction int           número de segundos a esperar antes de remover solicitações do cache (padrão 60)
   -interactions-poll-duration int      número de segundos a esperar antes de cada solicitação de polling de interações (padrão 5)
   -interactions-cooldown-period int    tempo adicional para o polling de interações antes de encerrar (padrão 5)
   -ni, -no-interactsh                  desativar o servidor interactsh para testes OAST, excluir templates baseados em OAST

FUZZING:
   -ft, -fuzzing-type string  sobrescreve o tipo de fuzzing definido no template (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string  sobrescreve o modo de fuzzing definido no template (multiple, single)
   -fuzz                      habilita o carregamento de templates de fuzzing (Obsoleto: usar -dast em vez disso)
   -dast                      executa apenas templates DAST

UNCOVER:
   -uc, -uncover                  ativa o motor uncover
   -uq, -uncover-query string[]   consulta de busca uncover
   -ue, -uncover-engine string[]  motor de busca uncover (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow) (padrão shodan)
   -uf, -uncover-field string     campos uncover a serem retornados (ip,port,host) (padrão "ip:port")
   -ul, -uncover-limit int        resultados uncover a serem retornados (padrão 100)
   -ur, -uncover-ratelimit int    sobrescreve o limite de taxa dos motores com o limite de taxa do motor uncover (padrão 60 req/min)

RATE-LIMIT:
   -rl, -rate-limit int               número máximo de solicitações a serem enviadas por segundo (padrão 150)
   -rlm, -rate-limit-minute int       número máximo de solicitações a serem enviadas por minuto
   -bs, -bulk-size int                número máximo de hosts a serem analisados em paralelo por template (padrão 25)
   -c, -concurrency int               número máximo de templates a serem executados em paralelo (padrão 25)
   -hbs, -headless-bulk-size int      número máximo de hosts headless a serem analisados em paralelo por template (padrão 10)
   -headc, -headless-concurrency int  número máximo de templates headless a serem executados em paralelo (padrão 10)
   -jsc, -js-concurrency int          número máximo de ambientes de execução de JavaScript a serem executados em paralelo (padrão 120)
   -pc, -payload-concurrency int      concorrência máxima de payload para cada template (padrão 25)

OPTIMIZATIONS:
   -timeout int                     tempo limite em segundos (padrão 10)
   -retries int                     número de tentativas para solicitações com falha (padrão 1)
   -ldp, -leave-default-ports       manter as portas HTTP/HTTPS padrão (exemplo: host:80, host:443)
   -mhe, -max-host-error int        número máximo de erros para um host antes de ignorá-lo no scan (padrão 30)
   -te, -track-error string[]       adiciona o erro especificado à lista de rastreamento de erros máximos por host (standard, file)
   -nmhe, -no-mhe                   desativa a exclusão de hosts do scan com base em erros
   -project                         utiliza uma pasta de projeto para evitar enviar a mesma solicitação várias vezes
   -project-path string             define um caminho específico para o projeto (padrão "/tmp")
   -spm, -stop-at-first-match       interrompe o processamento de solicitações HTTP após a primeira correspondência (pode quebrar a lógica de templates/fluxos de trabalho)
   -stream                          modo de transmissão - começa a trabalhar sem ordenar a entrada
   -ss, -scan-strategy value        estratégia a ser usada durante o scan (auto/host-spray/template-spray) (padrão auto)
   -irt, -input-read-timeout value  tempo limite para leitura da entrada (padrão 3m0s)
   -nh, -no-httpx                   desativa a análise httpx para entradas que não sejam URLs
   -no-stdin                        desativa o processamento de entrada padrão

HEADLESS:
   -headless                        habilita templates que requerem suporte para navegadores sem interface gráfica (headless browser) (o usuário root no Linux desativará o sandbox)
   -page-timeout int                segundos para esperar cada página no modo headless (padrão 20)
   -sb, -show-browser               exibe o navegador na tela ao executar templates no modo headless
   -ho, -headless-options string[]  inicia o Chrome no modo headless com opções adicionais
   -sc, -system-chrome              utiliza o navegador Chrome instalado localmente em vez do instalado pelo nuclei
   -lha, -list-headless-action      lista ações disponíveis para o modo headless

DEBUG:
   -debug                    exibe todas as solicitações e respostas
   -dreq, -debug-req         exibe todas as solicitações enviadas
   -dresp, -debug-resp       exibe todas as respostas recebidas
   -p, -proxy string[]       lista de proxies HTTP/SOCKS5 a serem usados (separados por vírgulas ou arquivo de entrada)
   -pi, -proxy-internal      proxy para todas as solicitações internas
   -ldf, -list-dsl-function  lista todas as assinaturas de funções DSL suportadas
   -tlog, -trace-log string  arquivo para gravar o log de rastreamento de solicitações enviadas
   -elog, -error-log string  arquivo para gravar o log de erros de solicitações enviadas
   -version                  exibe a versão do nuclei
   -hm, -hang-monitor        ativa o monitoramento de travamentos do nuclei
   -v, -verbose              exibe saída detalhada
   -profile-mem string       arquivo opcional para despejo de memória do nuclei
   -vv                       exibe os templates carregados para o scan
   -svd, -show-var-dump      exibe o dump de variáveis para depuração
   -ep, -enable-pprof        ativa o servidor de depuração pprof
   -tv, -templates-version   exibe a versão dos templates do nuclei (nuclei-templates) instalados
   -hc, -health-check        executa verificações de diagnóstico

UPDATE:
   -up, -update                      atualiza o mecanismo do nuclei para a última versão lançada
   -ut, -update-templates            atualiza os nuclei-templates para a última versão lançada
   -ud, -update-template-dir string  diretório personalizado para instalar/atualizar os nuclei-templates
   -duc, -disable-update-check       desativa a verificação automática de atualizações do nuclei/templates

STATISTICS:
   -stats                    exibe estatísticas sobre o scan em execução
   -sj, -stats-json          exibe estatísticas no formato JSONL(ines)
   -si, -stats-interval int  número de segundos a esperar entre as atualizações de estatísticas (padrão 5)
   -mp, -metrics-port int    porta para expor métricas do nuclei (padrão 9092)

CLOUD:
   -auth                  configura a chave de API do cloud do ProjectDiscovery (pdcp)
   -cup, -cloud-upload    faz upload dos resultados do scan para o dashboard do pdcp
   -sid, -scan-id string  faz upload dos resultados do scan para o ID de scan fornecido

AUTHENTICATION:
   -sf, -secret-file string[]  caminho para o arquivo de configuração contendo os secrets para o scan autenticado do nuclei
   -ps, -prefetch-secrets      pré-carrega os secrets do arquivo de secrets


EXAMPLES:
Executar nuclei em um único host:
   $ nuclei -target example.com

Executar nuclei com diretórios específicos de templates:
   $ nuclei -target example.com -t http/cves/ -t ssl

Executar nuclei contra uma lista de hosts:
   $ nuclei -list hosts.txt

Executar nuclei com saída JSON:
   $ nuclei -target example.com -json-export output.json

Executar nuclei com saídas Markdown organizadas (com variáveis de ambiente):
   $ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

Documentação adicional disponível em: https://docs.nuclei.sh/getting-started/running
```

### Executando Nuclei

Consulte https://docs.projectdiscovery.io/tools/nuclei/running para obter detalhes sobre como executar o Nuclei.

### Uso de Nuclei com código Go

O guia completo sobre como usar o Nuclei como biblioteca/SDK está disponível em [godoc](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib#section-readme).


### Recursos

Você pode acessar a documentação principal do Nuclei em https://docs.projectdiscovery.io/tools/nuclei/ e obter mais informações sobre o Nuclei na nuvem com a [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io).

Consulte https://docs.projectdiscovery.io/tools/nuclei/resources para acessaar mais recursos e vídeos sobre o Nuclei!

### Créditos

Obrigado a todos os incríveis [contribuidores da comunidade que enviaram em PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors) e mantêm este projeto atualizado. :heart:

Se você tem uma ideia ou algum tipo de melhoria, sinta-se à vontade para contribuir e participar do projeto. Envie seu PR!

<p align="center">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=projectdiscovery/nuclei&max=500">
</a>
</p>


Confira também os seguintes projetos de código aberto que podem se adequar ao seu fluxo de trabalho:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### Licença

O Nuclei é distribuído sob a [Licença MIT](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://docs.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
