$ErrorActionPreference = "Stop"

function New-Certificate([string] $base64) {
  return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [Convert]::FromBase64String($base64)
  )
}

function Add-Intermediates($chain, $intermediates) {
  foreach ($item in @($intermediates)) {
    if ($item) {
      [void] $chain.ChainPolicy.ExtraStore.Add((New-Certificate $item))
    }
  }
}

function Get-ChainStatuses($chain) {
  return @(
    $chain.ChainStatus |
      ForEach-Object { $_.Status.ToString() } |
      Where-Object { $_ -and $_ -ne "NoError" } |
      Select-Object -Unique
  )
}

function Get-CertificateSha256($certificate) {
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($sha256.ComputeHash($certificate.RawData))).Replace("-", "")
  } finally {
    $sha256.Dispose()
  }
}

$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$leaf = New-Certificate $payload.leaf
$verificationTime = [DateTime]::Parse(
  [string] $payload.verificationTime,
  [Globalization.CultureInfo]::InvariantCulture,
  [Globalization.DateTimeStyles]::RoundtripKind
)

$trustChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$trustChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$trustChain.ChainPolicy.VerificationTime = $verificationTime
$trustChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
Add-Intermediates $trustChain $payload.intermediates
$nativeChainTrusted = $trustChain.Build($leaf)
$statuses = @(Get-ChainStatuses $trustChain)
$rootCertificate = if ($trustChain.ChainElements.Count -gt 0) {
  $trustChain.ChainElements[$trustChain.ChainElements.Count - 1].Certificate
} else {
  $null
}
$rootSha256 = if ($rootCertificate) { Get-CertificateSha256 $rootCertificate } else { "" }
$trustedRootSha256 = @($payload.trustedRootSha256 | ForEach-Object { ([string] $_).ToUpperInvariant() })
$customRootTrusted = (
  $rootSha256 -and
  ($trustedRootSha256 -contains $rootSha256) -and
  @($statuses | Where-Object { $_ -ne "UntrustedRoot" }).Count -eq 0
)
$chainTrusted = $nativeChainTrusted -or $customRootTrusted

$revocationStatus = "not-checked"
if ($chainTrusted) {
  $revocationChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
  $revocationChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
  $revocationChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
  $revocationChain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(4)
  $revocationChain.ChainPolicy.VerificationTime = $verificationTime
  Add-Intermediates $revocationChain $payload.intermediates
  $revocationValid = $revocationChain.Build($leaf)
  $revocationStatuses = @(Get-ChainStatuses $revocationChain)
  $statuses = @($statuses + $revocationStatuses | Select-Object -Unique)
  $relevantRevocationStatuses = @($revocationStatuses | Where-Object { $_ -ne "UntrustedRoot" })
  if ($revocationValid -or ($customRootTrusted -and $relevantRevocationStatuses.Count -eq 0)) {
    $revocationStatus = "valid"
  } elseif ($relevantRevocationStatuses -contains "Revoked") {
    $revocationStatus = "revoked"
  } elseif (
    ($relevantRevocationStatuses -contains "RevocationStatusUnknown") -or
    ($relevantRevocationStatuses -contains "OfflineRevocation")
  ) {
    $revocationStatus = "unknown"
  } else {
    $revocationStatus = "invalid"
  }
}

@{
  chainTrusted = [bool] $chainTrusted
  revocationStatus = $revocationStatus
  statuses = $statuses
  rootSha256 = $rootSha256
} | ConvertTo-Json -Compress
