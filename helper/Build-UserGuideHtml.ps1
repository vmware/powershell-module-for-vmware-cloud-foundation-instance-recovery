# © Broadcom. All Rights Reserved.
# The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-2

<#
.SYNOPSIS
Builds help\VCF-RecoveryCoordinator-UserGuide.html from docs\user-guide.md.

.DESCRIPTION
The Recovery Coordinator UI's Help link opens the generated file in the default browser. The Markdown
file stays the single source of truth (it is also published to the documentation site); re-run this script
after editing it and commit the regenerated HTML.

The output is one fully self-contained file -- inline CSS and a few lines of inline JavaScript, no web
fonts, no CDN, no network requests -- so it works on the air-gapped machines recoveries are often run
from. The styling follows the VMware Clarity design language (vertical navigation, alerts, tables, type
scale) using the same palette as the application window; the Clarity library itself is not bundled.

Requires PowerShell 7 (ConvertFrom-Markdown).

.EXAMPLE
./helper/Build-UserGuideHtml.ps1
#>

[CmdletBinding()]
Param(
    [string] $SourcePath = (Join-Path (Join-Path $PSScriptRoot '..') 'docs/user-guide.md'),
    [string] $OutputPath = (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'help') 'VCF-RecoveryCoordinator-UserGuide.html')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SourcePath)) {
    throw "Source '$SourcePath' was not found."
}
$markdown = (Get-Content -LiteralPath $SourcePath -Raw) -replace "`r`n", "`n"

# --- Admonitions ----------------------------------------------------------------------------------
# MkDocs "!!! type "Title"" blocks (body indented four spaces) aren't standard Markdown. Each one is
# pulled out, its body rendered on its own, and swapped back in as a Clarity-style alert after the main
# render, via a placeholder paragraph.
$alerts = [System.Collections.Generic.List[object]]::new()
$lines = $markdown -split "`n"
$kept = [System.Collections.Generic.List[string]]::new()
$inCodeFence = $false
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match '^\s*```') { $inCodeFence = -not $inCodeFence }
    if (-not $inCodeFence -and $line -match '^!!!\s+(\w+)(?:\s+"([^"]*)")?\s*$') {
        $type = $Matches[1].ToLower()
        $title = $Matches[2]
        $body = [System.Collections.Generic.List[string]]::new()
        $i++
        while ($i -lt $lines.Count -and ($lines[$i] -match '^    ' -or $lines[$i].Trim() -eq '')) {
            [void]$body.Add(($lines[$i] -replace '^    ', ''))
            $i++
        }
        $i--
        while ($body.Count -gt 0 -and $body[$body.Count - 1].Trim() -eq '') { $body.RemoveAt($body.Count - 1) }
        [void]$alerts.Add([pscustomobject]@{ Type = $type; Title = $title; Body = ($body -join "`n") })
        [void]$kept.Add('')
        [void]$kept.Add("ALERTPLACEHOLDER$($alerts.Count - 1)X")
        [void]$kept.Add('')
        continue
    }
    [void]$kept.Add($line)
}
$markdown = $kept -join "`n"

$html = (ConvertFrom-Markdown -InputObject $markdown).Html

$alertClass = @{ note = 'alert-info'; info = 'alert-info'; tip = 'alert-success'; warning = 'alert-warning'; danger = 'alert-danger' }
$alertLabel = @{ note = 'Note'; info = 'Info'; tip = 'Tip'; warning = 'Warning'; danger = 'Important' }
for ($n = 0; $n -lt $alerts.Count; $n++) {
    $alert = $alerts[$n]
    $cssClass = if ($alertClass.ContainsKey($alert.Type)) { $alertClass[$alert.Type] } else { 'alert-info' }
    $title = if ($alert.Title) { $alert.Title } elseif ($alertLabel.ContainsKey($alert.Type)) { $alertLabel[$alert.Type] } else { (Get-Culture).TextInfo.ToTitleCase($alert.Type) }
    $bodyHtml = (ConvertFrom-Markdown -InputObject $alert.Body).Html
    $titleHtml = [System.Net.WebUtility]::HtmlEncode($title)
    $block = "<div class=`"alert $cssClass`" role=`"note`"><div class=`"alert-icon`" aria-hidden=`"true`"></div><div class=`"alert-content`"><div class=`"alert-title`">$titleHtml</div>$bodyHtml</div></div>"
    $html = $html.Replace("<p>ALERTPLACEHOLDER$($n)X</p>", $block)
}

# --- Title and navigation -------------------------------------------------------------------------
$pageTitle = 'Recovery Coordinator User Guide'
if ($html -match '(?s)<h1[^>]*>(.*?)</h1>') {
    $pageTitle = [System.Net.WebUtility]::HtmlDecode(($Matches[1] -replace '<[^>]+>', ''))
    $html = [regex]::Replace($html, '(?s)<h1[^>]*>.*?</h1>', '', 1)
}

# The hand-written "Contents" list duplicates the sidebar, so it is dropped from the page body.
$html = [regex]::Replace($html, '(?s)<h2 id="contents">Contents</h2>\s*<ul>.*?</ul>\s*', '', 1)
$html = $html -replace '<hr />', ''

# Relative links to sibling documentation pages don't resolve from a standalone file, so point them at
# the published documentation site.
$siteRoot = 'https://vmware.github.io/powershell-module-for-vmware-cloud-foundation-instance-recovery'
$html = [regex]::Replace($html, 'href="([\w-]+)\.md(#[^"]*)?"', { param($m) "href=`"$siteRoot/$($m.Groups[1].Value)/$($m.Groups[2].Value)`" target=`"_blank`" rel=`"noopener`"" })

$nav = [System.Text.StringBuilder]::new()
$headingMatches = [regex]::Matches($html, '<h([23]) id="([^"]+)">(.*?)</h\1>')
foreach ($m in $headingMatches) {
    $level = $m.Groups[1].Value
    $text = ($m.Groups[3].Value -replace '<[^>]+>', '')
    [void]$nav.AppendLine("<a class=`"nav-link nav-l$level`" href=`"#$($m.Groups[2].Value)`">$text</a>")
}

# --- Code blocks: add a language label the CSS can show --------------------------------------------
$html = [regex]::Replace($html, '<pre><code class="language-(\w+)">', { param($m) "<pre data-lang=`"$($m.Groups[1].Value)`"><code>" })
# Screenshots: Markdown image links are resolved relative to the source file and embedded as data URIs, so
# the HTML stays a single self-contained file. A missing image is left out (with a warning) rather than
# shown as a broken-image icon.
$sourceDirectory = Split-Path -Path (Resolve-Path -LiteralPath $SourcePath).Path -Parent
$mimeTypes = @{ png = 'image/png'; jpg = 'image/jpeg'; jpeg = 'image/jpeg'; gif = 'image/gif'; svg = 'image/svg+xml' }
$html = [regex]::Replace($html, '<p><img src="([^"]+)" alt="([^"]*)" /></p>', {
        param($m)
        $source = $m.Groups[1].Value
        $altText = $m.Groups[2].Value
        if ($source -match '^(https?:|data:)') { return $m.Value }
        $imagePath = Join-Path $sourceDirectory ([System.Uri]::UnescapeDataString($source))
        if (-not (Test-Path -LiteralPath $imagePath)) {
            Write-Warning "Image '$source' was not found; it is omitted from the HTML."
            return ''
        }
        $extension = [System.IO.Path]::GetExtension($imagePath).TrimStart('.').ToLower()
        $mime = if ($mimeTypes.ContainsKey($extension)) { $mimeTypes[$extension] } else { 'application/octet-stream' }
        $data = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($imagePath))
        "<figure><img src=`"data:$mime;base64,$data`" alt=`"$altText`" loading=`"lazy`"><figcaption>$altText</figcaption></figure>"
    })
$html = $html.Replace('<table>', '<div class="table-wrap"><table class="table">').Replace('</table>', '</table></div>')

$moduleVersion = ''
$manifest = Join-Path (Join-Path $PSScriptRoot '..') 'VCF.RecoveryCoordinator.psd1'
if (Test-Path -LiteralPath $manifest) {
    $versionMatch = [regex]::Match((Get-Content -LiteralPath $manifest -Raw), "(?<=ModuleVersion\s*=\s*')[^']+")
    if ($versionMatch.Success) { $moduleVersion = $versionMatch.Value }
}
$versionHtml = if ($moduleVersion) { "<span class=`"version`">v$moduleVersion</span>" } else { '' }

$css = @'
:root {
  --header: #1D2731; --accent: #0095D3; --accent-hover: #0077AA; --text: #22313F; --subtle: #6B7280;
  --bg: #F5F5F5; --panel: #FFFFFF; --border: #E0E0E0; --hover-bg: #EAF6FC; --code-bg: #F1F3F5;
  --info: #0072A3; --info-bg: #E1F1F6; --success: #2E7D32; --success-bg: #E7F4E8;
  --warning: #B26A00; --warning-bg: #FFF4DB; --danger: #C21D00; --danger-bg: #FBE9E7;
  --font: "Clarity City", "Metropolis", "Avenir Next", Avenir, "Segoe UI", -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: "Consolas", "SFMono-Regular", Menlo, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 76px; }
body { margin: 0; font-family: var(--font); font-size: 16px; line-height: 1.6; color: var(--text); background: var(--bg); }
.header { position: fixed; top: 0; left: 0; right: 0; height: 60px; background: var(--header); color: #fff; display: flex; align-items: center; padding: 0 24px; z-index: 10; }
.header .brand { display: flex; flex-direction: column; line-height: 1.2; }
.header .brand .l1 { font-size: 15px; font-weight: 600; }
.header .brand .l2 { font-size: 14px; color: #B9C2CC; }
.header .spacer { flex: 1; }
.header .version { color: #B9C2CC; font-size: 13px; }
.layout { display: flex; padding-top: 60px; min-height: 100vh; }
.sidenav { position: fixed; top: 60px; bottom: 0; width: 290px; overflow-y: auto; background: var(--panel); border-right: 1px solid var(--border); padding: 16px 0 32px; }
.sidenav .nav-title { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--subtle); font-weight: 600; padding: 4px 24px 8px; }
.nav-link { display: block; color: var(--text); text-decoration: none; font-size: 14px; line-height: 1.35; padding: 6px 24px; border-left: 3px solid transparent; }
.nav-link.nav-l3 { padding-left: 40px; font-size: 13px; color: var(--subtle); }
.nav-link:hover { background: var(--hover-bg); color: var(--accent-hover); }
.nav-link.active { border-left-color: var(--accent); background: var(--hover-bg); color: var(--accent-hover); font-weight: 600; }
.content { margin-left: 290px; width: calc(100% - 290px); padding: 32px 48px 80px; }
.content-inner { max-width: 900px; }
.doc-title { font-size: 2.2rem; font-weight: 200; margin: 0 0 4px; letter-spacing: -.01em; }
.doc-sub { color: var(--subtle); margin: 0 0 28px; }
h2 { font-size: 1.65rem; font-weight: 300; margin: 2.6rem 0 .8rem; padding-bottom: .35rem; border-bottom: 1px solid var(--border); }
h3 { font-size: 1.2rem; font-weight: 600; margin: 2rem 0 .5rem; }
h4 { font-size: 1rem; font-weight: 600; margin: 1.5rem 0 .4rem; }
p { margin: .7rem 0; }
a { color: var(--accent-hover); }
ul, ol { padding-left: 1.6rem; }
li { margin: .25rem 0; }
li > p { margin: .35rem 0; }
code { font-family: var(--mono); font-size: .88em; background: var(--code-bg); border: 1px solid #E3E6EA; border-radius: 3px; padding: 1px 5px; }
pre { position: relative; background: var(--header); color: #E6EDF3; border-radius: 4px; padding: 16px 18px; overflow-x: auto; font-size: 13.5px; line-height: 1.5; margin: 1rem 0; }
pre code { background: none; border: 0; padding: 0; color: inherit; font-size: inherit; }
pre[data-lang]::before { content: attr(data-lang); position: absolute; top: 6px; right: 12px; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: #8DA2B5; }
.table-wrap { overflow-x: auto; margin: 1rem 0; }
table.table { border-collapse: collapse; width: 100%; background: var(--panel); font-size: 14.5px; }
table.table th { text-align: left; font-weight: 600; font-size: 13px; color: var(--text); background: #FAFAFA; border-top: 1px solid var(--border); border-bottom: 2px solid #C1CDD4; padding: 10px 14px; white-space: nowrap; }
table.table td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
table.table tr:hover td { background: var(--hover-bg); }
table.table td:first-child { white-space: nowrap; }
.alert { display: flex; border: 1px solid; border-radius: 3px; margin: 1.2rem 0; overflow: hidden; background: var(--panel); }
.alert-icon { flex: 0 0 38px; display: flex; align-items: flex-start; justify-content: center; padding-top: 12px; color: #fff; font-weight: 700; font-size: 15px; }
.alert-content { padding: 10px 16px 12px; }
.alert-title { font-weight: 700; margin-bottom: 2px; }
.alert-content p:first-of-type { margin-top: 0; }
.alert-content p:last-child, .alert-content ul:last-child { margin-bottom: 0; }
.alert-info { border-color: var(--info); background: var(--info-bg); } .alert-info .alert-icon { background: var(--info); } .alert-info .alert-icon::before { content: "i"; font-style: italic; font-family: Georgia, serif; }
.alert-success { border-color: var(--success); background: var(--success-bg); } .alert-success .alert-icon { background: var(--success); } .alert-success .alert-icon::before { content: "\2713"; }
.alert-warning { border-color: var(--warning); background: var(--warning-bg); } .alert-warning .alert-icon { background: var(--warning); } .alert-warning .alert-icon::before { content: "!"; }
.alert-danger { border-color: var(--danger); background: var(--danger-bg); } .alert-danger .alert-icon { background: var(--danger); } .alert-danger .alert-icon::before { content: "!"; }
blockquote { margin: 1rem 0; padding: .5rem 1rem; border-left: 4px solid var(--accent); background: var(--hover-bg); color: var(--text); }
blockquote p { margin: .3rem 0; }
figure { margin: 1.4rem 0; } figure img { display: block; max-width: 100%; height: auto; border: 1px solid var(--border); border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,.12); background: var(--panel); }
figcaption { margin-top: 8px; font-size: 13px; color: var(--subtle); text-align: center; }
.footer { margin-top: 4rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--subtle); font-size: 13px; }
@media (max-width: 900px) { .sidenav { display: none; } .content { margin-left: 0; width: 100%; padding: 24px 20px 60px; } }
@media print {
  .header, .sidenav { display: none; } .layout { padding-top: 0; } .content { margin: 0; width: 100%; padding: 0; }
  body { background: #fff; font-size: 11pt; } pre { background: #F1F3F5; color: #000; border: 1px solid #ccc; white-space: pre-wrap; }
  .alert, table.table tr { page-break-inside: avoid; } h2, h3 { page-break-after: avoid; }
}
'@

$js = @'
(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll('.nav-link'));
  var targets = links.map(function (a) { return document.getElementById(a.getAttribute('href').slice(1)); });
  function spy() {
    var current = 0, y = window.scrollY + 90;
    for (var i = 0; i < targets.length; i++) { if (targets[i] && targets[i].offsetTop <= y) current = i; }
    links.forEach(function (a, i) { a.classList.toggle('active', i === current); });
    if (links[current]) { var n = links[current], s = document.querySelector('.sidenav');
      if (n.offsetTop < s.scrollTop || n.offsetTop > s.scrollTop + s.clientHeight - 60) { s.scrollTop = n.offsetTop - 80; } }
  }
  window.addEventListener('scroll', spy, { passive: true }); spy();
})();
'@

$encodedTitle = [System.Net.WebUtility]::HtmlEncode($pageTitle)
$built = Get-Date -Format 'yyyy-MM-dd'
$document = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VMware Cloud Foundation Recovery Coordinator - $encodedTitle</title>
<style>
$css
</style>
</head>
<body>
<header class="header">
  <div class="brand"><span class="l1">VMware Cloud Foundation</span><span class="l2">Recovery Coordinator</span></div>
  <div class="spacer"></div>
  $versionHtml
</header>
<div class="layout">
  <nav class="sidenav" aria-label="Contents">
    <div class="nav-title">Contents</div>
$($nav.ToString())
  </nav>
  <main class="content">
    <div class="content-inner">
      <h1 class="doc-title">$encodedTitle</h1>
      <p class="doc-sub">Generated from the module documentation on $built.</p>
$html
      <div class="footer">&copy; Broadcom. All Rights Reserved. The term &ldquo;Broadcom&rdquo; refers to Broadcom Inc. and/or its subsidiaries.</div>
    </div>
  </main>
</div>
<script>
$js
</script>
</body>
</html>
"@

$outputDirectory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}
Set-Content -LiteralPath $OutputPath -Value $document -Encoding utf8
Write-Host "Wrote $((Resolve-Path -LiteralPath $OutputPath).Path)"
