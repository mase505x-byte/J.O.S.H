<#
Passive website security-header checker. Use only on sites you own or are
explicitly authorized to assess. Makes one page request; does not crawl or probe.
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true, Position = 0)]
	[string]$Url,

	[Parameter(Mandatory = $true)]
	[switch]$Authorized,

	[string]$ReportPath
)

if (-not $Authorized) {
	throw 'Confirm authorization by passing -Authorized.'
}

$target = $null
if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$target) -or
	$target.Scheme -notin @('http', 'https')) {
	throw 'Url must be an absolute HTTP or HTTPS address.'
}

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
	param([string]$Severity, [string]$Title, [string]$Detail, [string]$Location)
	$findings.Add([pscustomobject]@{
		severity = $Severity
		title    = $Title
		detail   = $Detail
		location = $Location
	})
}

$response = $null
$requestError = $null
try {
	# One ordinary page request only. No payloads, crawling, or endpoint guessing.
	$response = Invoke-WebRequest -Uri $target -Method Get -TimeoutSec 15 `
		-MaximumRedirection 5 -UserAgent 'AuthorizedPassiveSecurityCheck/1.0' `
		-UseBasicParsing -ErrorAction Stop
} catch {
	$requestError = $_.Exception.Message
	if ($_.Exception.Response) { $response = $_.Exception.Response }
}

$headers = @{}
$statusCode = $null
$finalUrl = $target.AbsoluteUri
if ($response) {
	try { $statusCode = [int]$response.StatusCode } catch { }
	if ($response.Headers) {
		foreach ($key in $response.Headers.Keys) {
			$headers[[string]$key] = [string]$response.Headers[$key]
		}
	}
	if ($response.BaseResponse -and $response.BaseResponse.ResponseUri) {
		$finalUrl = $response.BaseResponse.ResponseUri.AbsoluteUri
	} elseif ($response.BaseResponse -and $response.BaseResponse.RequestMessage) {
		$finalUrl = $response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
	}
}

if ($requestError -and -not $response) {
	Add-Finding 'error' 'Request failed' $requestError $target.AbsoluteUri
} else {
	$finalUri = [Uri]$finalUrl
	if ($target.Scheme -eq 'http' -and $finalUri.Scheme -ne 'https') {
		Add-Finding 'high' 'HTTPS is not enforced' 'The request did not end on HTTPS. Enable HTTPS and redirect HTTP traffic.' $target.AbsoluteUri
	}
	if ($finalUri.Scheme -eq 'https' -and -not $headers.ContainsKey('Strict-Transport-Security')) {
		Add-Finding 'medium' 'HSTS header missing' 'Consider Strict-Transport-Security after verifying HTTPS works site-wide.' $finalUri.AbsoluteUri
	}
	if (-not $headers.ContainsKey('Content-Security-Policy')) {
		Add-Finding 'medium' 'Content-Security-Policy missing' 'A carefully configured CSP can reduce the impact of content injection.' $finalUri.AbsoluteUri
	}
	if (-not $headers.ContainsKey('X-Content-Type-Options')) {
		Add-Finding 'low' 'X-Content-Type-Options missing' 'Consider setting X-Content-Type-Options: nosniff.' $finalUri.AbsoluteUri
	} elseif ($headers['X-Content-Type-Options'] -notmatch '(?i)\bnosniff\b') {
		Add-Finding 'low' 'Unexpected X-Content-Type-Options value' 'The header is present but does not specify nosniff.' $finalUri.AbsoluteUri
	}
	if (-not $headers.ContainsKey('Referrer-Policy')) {
		Add-Finding 'low' 'Referrer-Policy missing' 'Set an appropriate Referrer-Policy to limit referrer information.' $finalUri.AbsoluteUri
	}
	if (-not $headers.ContainsKey('Permissions-Policy')) {
		Add-Finding 'info' 'Permissions-Policy missing' 'Consider disabling browser features the site does not use.' $finalUri.AbsoluteUri
	}
	if (-not $headers.ContainsKey('X-Frame-Options') -and
		(-not $headers.ContainsKey('Content-Security-Policy') -or
		 $headers['Content-Security-Policy'] -notmatch '(?i)\bframe-ancestors\b')) {
		Add-Finding 'low' 'Framing protection not detected' 'Use CSP frame-ancestors or X-Frame-Options if framing is not intended.' $finalUri.AbsoluteUri
	}
	foreach ($name in @('Server', 'X-Powered-By')) {
		if ($headers.ContainsKey($name) -and $headers[$name]) {
			Add-Finding 'info' 'Technology disclosure header' "$name exposes: $($headers[$name])" $finalUri.AbsoluteUri
		}
	}
	foreach ($cookieHeader in @($headers['Set-Cookie'])) {
		if (-not $cookieHeader) { continue }
		if ($finalUri.Scheme -eq 'https' -and $cookieHeader -notmatch '(?i)(^|;\s*)Secure(?:;|$)') {
			Add-Finding 'medium' 'Cookie missing Secure flag' 'A Set-Cookie response header lacks Secure.' 'Set-Cookie response header'
		}
		if ($cookieHeader -notmatch '(?i)(^|;\s*)HttpOnly(?:;|$)') {
			Add-Finding 'low' 'Cookie missing HttpOnly flag' 'A Set-Cookie response header lacks HttpOnly; verify whether JavaScript access is needed.' 'Set-Cookie response header'
		}
		if ($cookieHeader -notmatch '(?i)(^|;\s*)SameSite=(Strict|Lax|None)(;|$)') {
			Add-Finding 'low' 'Cookie missing SameSite attribute' 'A Set-Cookie response header lacks a recognized SameSite attribute.' 'Set-Cookie response header'
		}
	}
}

$report = [pscustomobject]@{
	scannedAt    = (Get-Date).ToUniversalTime().ToString('o')
	requestedUrl = $target.AbsoluteUri
	finalUrl     = $finalUrl
	statusCode   = $statusCode
	requestError = $requestError
	scanType     = 'passive-single-request'
	findings     = @($findings)
}
$json = $report | ConvertTo-Json -Depth 6
if ($ReportPath) { $json | Set-Content -LiteralPath $ReportPath -Encoding UTF8 }
$json
