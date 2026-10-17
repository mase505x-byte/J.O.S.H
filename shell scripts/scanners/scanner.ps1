<#
.SYNOPSIS
  Performs bounded, non-invasive security checks on an authorized website.
.DESCRIPTION
  Uses GET requests only; does not submit forms, inject payloads, follow redirects,
  or attempt exploitation. Findings are indicators for manual review, not proof of
  vulnerabilities. Scan only sites you own or are authorized to assess.
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[string] $Url,

	[ValidateRange(1, 50)]
	[int] $MaxPages = 10,

	[string] $ReportPath = '.\scanner-report.json'
)

$ErrorActionPreference = 'Stop'
try {
	$startUri = [Uri]$Url
	if (-not $startUri.IsAbsoluteUri -or $startUri.Scheme -notin @('http', 'https')) {
		throw 'URL must be an absolute http:// or https:// address.'
	}
} catch {
	throw "Invalid URL '$Url': $($_.Exception.Message)"
}

$findings = [System.Collections.Generic.List[object]]::new()
$queue = [System.Collections.Generic.Queue[Uri]]::new()
$visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$queue.Enqueue($startUri)
$pagesScanned = 0

function Add-Finding {
	param([string]$Severity, [string]$Check, [string]$Location, [string]$Evidence, [string]$Recommendation)
	$findings.Add([pscustomobject]@{
		Severity = $Severity
		Check = $Check
		Location = $Location
		Evidence = $Evidence
		Recommendation = $Recommendation
	})
}

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)
$client.DefaultRequestHeaders.UserAgent.ParseAdd('JOSH-Passive-Scanner/1.0')

try {
	while ($queue.Count -gt 0 -and $pagesScanned -lt $MaxPages) {
		$pageUri = $queue.Dequeue()
		$pageKey = $pageUri.GetLeftPart([UriPartial]::Path)
		if (-not $visited.Add($pageKey)) { continue }
		$pagesScanned++

		$request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $pageUri)
		try {
			$response = $client.SendAsync($request).GetAwaiter().GetResult()
			$body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
		} catch {
			Add-Finding 'Info' 'Request failed' $pageUri.AbsoluteUri $_.Exception.Message 'Check the URL and network access. No exploit or retry was attempted.'
			$request.Dispose()
			continue
		}

		$status = [int]$response.StatusCode
		if ($status -ge 300 -and $status -lt 400) {
			$destination = if ($response.Headers.Location) { $response.Headers.Location.ToString() } else { '(none)' }
			Add-Finding 'Info' 'Redirect not followed' $pageUri.AbsoluteUri "HTTP $status; Location: $destination" 'Review the redirect destination; redirects are intentionally not followed.'
			$response.Dispose()
			$request.Dispose()
			continue
		}
		if ($status -ge 400) {
			Add-Finding 'Info' 'HTTP response' $pageUri.AbsoluteUri "Server returned HTTP $status." 'Review whether this endpoint should be publicly accessible.'
		}

		$headers = @{}
		foreach ($header in $response.Headers) { $headers[$header.Key.ToLowerInvariant()] = @($header.Value) }
		foreach ($header in $response.Content.Headers) { $headers[$header.Key.ToLowerInvariant()] = @($header.Value) }

		if ($pageUri.Scheme -eq 'http') {
			Add-Finding 'High' 'HTTPS not used' $pageUri.AbsoluteUri 'The page was fetched over unencrypted HTTP.' 'Serve the site over HTTPS and redirect HTTP requests to HTTPS.'
		} elseif (-not $headers.ContainsKey('strict-transport-security')) {
			Add-Finding 'Medium' 'HSTS missing' "$($pageUri.GetLeftPart([UriPartial]::Authority))/" 'Strict-Transport-Security response header was absent.' 'After confirming HTTPS works site-wide, configure an appropriate Strict-Transport-Security header.'
		}

		$headerChecks = @(
			@{ Name = 'content-security-policy'; Severity = 'Medium'; Title = 'Content Security Policy missing'; Fix = 'Define a restrictive Content-Security-Policy suitable for the application.' },
			@{ Name = 'x-content-type-options'; Severity = 'Low'; Title = 'MIME sniffing protection missing'; Fix = 'Set X-Content-Type-Options: nosniff.' },
			@{ Name = 'x-frame-options'; Severity = 'Low'; Title = 'Clickjacking protection header missing'; Fix = 'Set an appropriate frame-ancestors directive in CSP; consider X-Frame-Options for legacy clients.' },
			@{ Name = 'referrer-policy'; Severity = 'Low'; Title = 'Referrer policy missing'; Fix = 'Set a Referrer-Policy suitable for the site, such as strict-origin-when-cross-origin.' }
		)
		foreach ($check in $headerChecks) {
			if (-not $headers.ContainsKey($check.Name)) {
				Add-Finding $check.Severity $check.Title $pageUri.AbsoluteUri "$($check.Name) response header was absent." $check.Fix
			}
		}
		if ($headers.ContainsKey('server') -and ($headers['server'] -join ', ') -match '\d') {
			Add-Finding 'Info' 'Server version disclosed' "$($pageUri.AbsoluteUri) [Server header]" ($headers['server'] -join ', ') 'Consider suppressing detailed server and version tokens.'
		}
		if ($headers.ContainsKey('x-powered-by')) {
			Add-Finding 'Info' 'Technology header disclosed' "$($pageUri.AbsoluteUri) [X-Powered-By header]" ($headers['x-powered-by'] -join ', ') 'Remove unnecessary technology-identifying response headers.'
		}

		if ($headers.ContainsKey('set-cookie')) {
			foreach ($cookie in $headers['set-cookie']) {
				$cookieName = (($cookie -split '=', 2)[0]).Trim()
				$location = "$($pageUri.AbsoluteUri) [Set-Cookie: $cookieName]"
				if ($pageUri.Scheme -eq 'https' -and $cookie -notmatch '(?i)(^|;)\s*Secure(?:;|$)') {
					Add-Finding 'Medium' 'Cookie missing Secure flag' $location 'Set-Cookie did not include Secure.' 'Set Secure on cookies that should only be sent over HTTPS.'
				}
				if ($cookie -notmatch '(?i)(^|;)\s*HttpOnly(?:;|$)') {
					Add-Finding 'Low' 'Cookie missing HttpOnly flag' $location 'Set-Cookie did not include HttpOnly.' 'Set HttpOnly on cookies that do not need to be read by client-side scripts.'
				}
				if ($cookie -notmatch '(?i)(^|;)\s*SameSite\s*=') {
					Add-Finding 'Low' 'Cookie missing SameSite attribute' $location 'Set-Cookie did not include SameSite.' 'Choose an appropriate SameSite policy, commonly Lax, based on application behavior.'
				}
			}
		}

		$lineNumber = 0
		foreach ($line in ($body -split "`n")) {
			$lineNumber++
			if ($line -match '(?is)<form\b[^>]*\baction\s*=\s*["'']\s*http://') {
				Add-Finding 'High' 'Form submits over HTTP' "$($pageUri.AbsoluteUri) [line $lineNumber]" $line.Trim() 'Submit forms only over HTTPS; do not send credentials or sensitive data over HTTP.'
			}
			if ($pageUri.Scheme -eq 'https' -and $line -match '(?is)(src|href)\s*=\s*["'']http://') {
				Add-Finding 'Medium' 'Potential mixed content' "$($pageUri.AbsoluteUri) [line $lineNumber]" $line.Trim() 'Serve referenced resources over HTTPS and review browser mixed-content warnings.'
			}
		}

		# Follow only same-origin HTML links without query strings. Never submit forms.
		$mediaType = ''
		if ($response.Content.Headers.ContentType) { $mediaType = $response.Content.Headers.ContentType.MediaType }
		if ($pagesScanned -lt $MaxPages -and $mediaType -eq 'text/html') {
			foreach ($match in [regex]::Matches($body, '(?is)<a\b[^>]*?\bhref\s*=\s*["'']([^"'']+)["'']')) {
				$href = [System.Net.WebUtility]::HtmlDecode($match.Groups[1].Value).Trim()
				if (-not $href -or $href.StartsWith('#') -or $href -match '^(?i)(mailto:|javascript:|tel:)') { continue }
				try {
					$link = [Uri]::new($pageUri, $href)
					if ($link.Scheme -eq $startUri.Scheme -and $link.Host -eq $startUri.Host -and $link.Port -eq $startUri.Port -and -not $link.Query -and -not $link.Fragment -and $link.AbsolutePath -notmatch '(?i)\.(png|jpe?g|gif|svg|css|js|ico|pdf|zip|woff2?)$') {
						$linkKey = $link.GetLeftPart([UriPartial]::Path)
						if (-not $visited.Contains($linkKey)) { $queue.Enqueue($link) }
					}
				} catch { }
			}
		}
		$response.Dispose()
		$request.Dispose()
	}
} finally {
	$client.Dispose()
	$handler.Dispose()
}

$report = [pscustomobject]@{
	Target = $startUri.AbsoluteUri
	ScannedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
	PagesScanned = $pagesScanned
	Scope = 'Bounded same-origin GET requests; passive checks only; no form submission, payload injection, or exploitation.'
	Findings = @($findings)
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
$report
Write-Host "`nReport saved to: $((Resolve-Path -LiteralPath $ReportPath).Path)"
