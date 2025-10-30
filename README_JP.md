<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">シンプルなYAMLベースのDSLに基づいた高速でカスタマイズ可能な脆弱性スキャナー</h4>

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
  <a href="#how-it-works">動作原理</a> •
  <a href="#install-nuclei">インストール</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/">ドキュメント</a> •
  <a href="#credits">クレジット</a> •
  <a href="https://docs.projectdiscovery.io/tools/nuclei/faq">FAQ</a> •
  <a href="https://discord.gg/projectdiscovery">Discordに参加</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">英語</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">中国語</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">韓国語</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ID.md">インドネシア語</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">スペイン語</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_PT-BR.md">ポルトガル語</a>
</p>

---

Nucleiは、テンプレートに基づいてターゲット間でリクエストを送信するために使用され、偽陽性がゼロであり、多数のホストで高速なスキャンを提供します。Nucleiは、TCP、DNS、HTTP、SSL、ファイル、Whois、Websocket、Headless、Codeなど、さまざまなプロトコルのスキャンを提供します。強力で柔軟なテンプレートを使用して、Nucleiはすべての種類のセキュリティチェックをモデル化するために使用できます。

**300人以上の** セキュリティ研究者およびエンジニアが提供するさまざまなタイプの脆弱性テンプレートを収容する[専用リポジトリ](https://github.com/projectdiscovery/nuclei-templates)を持っています。

## 動作原理

<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>

| :exclamation:  **免責事項**  |
|---------------------------------|
| **このプロジェクトは積極的に開発されています**。リリースによって重大な変更が発生することがあります。更新する前にリリースの変更ログを確認してください。 |
| このプロジェクトは主にスタンドアロンのCLIツールとして使用されることを目的として構築されました。**Nucleiをサービスとして実行すると、セキュリティリスクが生じる可能性があります。**注意して使用し、追加のセキュリティ対策を講じることをお勧めします。 |

# Nucleiのインストール

Nucleiを正常にインストールするには、**go1.22**が必要です。以下のコマンドを実行して最新バージョンをインストールしてください -

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

**より多くのインストール方法は[こちら](https://docs.projectdiscovery.io/tools/nuclei/install)で見つけることができます。**

<table>
<tr>
<td>  

### Nucleiテンプレート

Nucleiは、バージョン[v2.5.2](https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2)以降、デフォルトでテンプレートの自動ダウンロード/更新をサポートしています。[**Nuclei-Templates**](https://github.com/projectdiscovery/nuclei-templates)プロジェクトは、常に更新されるコミュニティ提供の即時使用可能なテンプレートのリストを提供します。

`update-templates`フラグを使用して、いつでもNucleiテンプレートを更新することができます。Nucleiの[テンプレートガイド](https://docs.projectdiscovery.io/templates/)に従って、個々のワークフローとニーズに合わせた独自のチェックを作成することができます。

YAML DSLの構文リファレンスは[こちら](SYNTAX-REFERENCE.md)で確認できます。

</td>
</tr>
</table>

### 使用方法

```sh
nuclei -h
```

これにより、ツールのヘルプが表示されます。ここには、サポートされているすべてのスイッチがあります。

```console
Nucleiは、広範な設定可能性、大規模な拡張性、および使いやすさに焦点を当てた、
高速でテンプレートベースの脆弱性スキャナーです。

使用法:
  ./nuclei [flags]

フラグ:
ターゲット:
   -u, -target string[]          スキャンする対象のURL/ホスト
   -l, -list string              スキャンする対象のURL/ホストのリストが含まれているファイルへのパス（1行に1つ）
   -resume string                resume.cfgを使用してスキャンを再開（クラスタリングは無効になります）
   -sa, -scan-all-ips            DNSレコードに関連付けられているすべてのIPをスキャン
   -iv, -ip-version string[]     ホスト名のスキャンするIPバージョン（4,6）-（デフォルトは4）

テンプレート:
   -nt, -new-templates                    最新のnuclei-templatesリリースに追加された新しいテンプレートのみを実行
   -ntv, -new-templates-version string[]  特定のバージョンに追加された新しいテンプレートを実行
   -as, -automatic-scan                   wappalyzer技術検出をタグマッピングに使用した自動Webスキャン
   -t, -templates string[]                実行するテンプレートまたはテンプレートディレクトリのリスト（カンマ区切り、ファイル）
   -turl, -template-url string[]          実行するテンプレートのURLまたはテンプレートURLのリスト（カンマ区切り、ファイル）
   -w, -workflows string[]                実行するワークフローまたはワークフローディレクトリのリスト（カンマ区切り、ファイル）
   -wurl, -workflow-url string[]          実行するワークフローのURLまたはワークフローURLのリスト（カンマ区切り、ファイル）
   -validate                              Nucleiに渡されたテンプレートを検証
   -nss, -no-strict-syntax                テンプレートで厳密な構文チェックを無効にする
   -td, -template-display                 テンプレートの内容を表示
   -tl                                    利用可能なすべてのテンプレートをリスト
   -sign                                  NUCLEI_SIGNATURE_PRIVATE_KEY環境変数で定義された秘密鍵でテンプレートに署名
   -code                                  コードプロトコルベースのテンプレートのロードを有効にする

フィルタリング:
   -a, -author string[]               作者に基づいて実行するテンプレート（カンマ区切り、ファイル）
   -tags string[]                     タグに基づいて実行するテンプレート（カンマ区切り、ファイル）
   -etags, -exclude-tags string[]     タグに基づいて除外するテンプレート（カンマ区切り、ファイル）
   -itags, -include-tags string[]     デフォルトまたは設定によって除外されている場合でも実行する必要があるタグ
   -id, -template-id string[]         テンプレートIDに基づいて実行するテンプレート（カンマ区切り、ファイル）
   -eid, -exclude-id string[]         テンプレートIDに基づいて除外するテンプレート（カンマ区切り、ファイル）
   -it, -include-templates string[]   デフォルトまたは設定によって除外されている場合でも実行する必要があるテンプレート
   -et, -exclude-templates string[]   除外するテンプレートまたはテンプレートディレクトリへのパス（カンマ区切り、ファイル）
   -em, -exclude-matchers string[]    結果で除外するテンプレートマッチャー
   -s, -severity value[]              重大度に基づいて実行するテンプレート。可能な値：info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]     重大度に基づいて除外するテンプレート。可能な値：info, low, medium, high, critical, unknown
   -pt, -type value[]                 プロトコルタイプに基づいて実行するテンプレート。可能な値：dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        プロトコルタイプに基づいて除外するテンプレート。可能な値：dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  式条件に基づいて実行するテンプレート

出力:
   -o, -output string            発見された問題/脆弱性を書き込む出力ファイル
   -sresp, -store-resp           Nucleiを通じて渡されたすべてのリクエスト/レスポンスを出力ディレクトリに保存
   -srd, -store-resp-dir string  Nucleiを通じて渡されたすべてのリクエスト/レスポンスをカスタムディレクトリに保存（デフォルトは「output」）
   -silent                       結果のみを表示
   -nc, -no-color                出力内容の着色を無効にする（ANSIエスケープコード）
   -j, -jsonl                    JSONL(ines)形式で出力を書き込む
   -irr, -include-rr -omit-raw   JSON、JSONL、Markdown出力にリクエスト/レスポンスペアを含める（発見のみ）[非推奨 -omit-raw使用]（デフォルトはtrue）
   -or, -omit-raw                JSON、JSONL、Markdown出力でリクエスト/レスポンスペアを省略する（発見のみ）
   -ot, -omit-template           JSON、JSONL出力でエンコードされたテンプレートを省略
   -nm, -no-meta                 CLI出力で結果のメタデータの印刷を無効にする
   -ts, -timestamp               CLI出力にタイムスタンプを印刷することを有効にする
   -rdb, -report-db string       Nucleiレポートデータベース（レポートデータを永続化するために常にこれを使用）
   -ms, -matcher-status          マッチ失敗のステータスを表示
   -me, -markdown-export string  Markdown形式で結果をエクスポートするディレクトリ
   -se, -sarif-export string     SARIF形式で結果をエクスポートするファイル
   -je, -json-export string      JSON形式で結果をエクスポートするファイル
   -jle, -jsonl-export string    JSONL(ine)形式で結果をエクスポートするファイル

設定:
   -config string                        Nucleiの設定ファイルへのパス
   -fr, -follow-redirects                HTTPテンプレートのリダイレクトをフォローすることを有効にする
   -fhr, -follow-host-redirects         