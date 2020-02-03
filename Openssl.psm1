
function New-OpenSSlPfx { param(
  [Parameter(Mandatory=$true, Position=0)][String]$CommonName,
  [Int]$KeySize = 4096,
  [Int]$Days = 365,
  [String]$OpenSslPath,
  [Switch]$AsCmsRecipient,
  [Switch]$AsBase64
)

if(!$OpenSslPath){
 
 $srcPath = (Get-Command -Name openssl -ErrorAction SilentlyContinue).Source
 $gitPath = [System.IO.FileInfo]"C:\Program Files\Git\mingw64\bin\openssl.exe"
 $aliasPath = (Get-Alias -Name openssl -ErrorAction SilentlyContinue).Definition

 $OpenSslPath = If($srcPath) { $srcPath }
 elseif($gitPath.Exists){ $gitPath.FullName }
 elseif($aliasPath) {$aliasPath}
 else {Throw "Can't locate openssl executable. Use OpenSslPathParameter to specify the location"} 
  
}

$OpenSslVersion = &$OpenSslPath "version"

if($AsCmsRecipient) {
if($OpenSslVersion -notlike '*1.1.1*') { Throw "cli extensions are not supported by this version ($OpenSslVersion). v1.1.1 is required"}
 $cmsExt = "-addext extendedKeyUsage=1.3.6.1.4.1.311.80.1 -addext keyUsage=keyEncipherment"
}

$in = [System.Diagnostics.Process]::new()
$in.StartInfo.Arguments = "req -x509 -sha256 -newkey rsa:$KeySize -keyout - -nodes -days $Days  -subj /CN=$CommonName  $cmsExt"
$in.StartInfo.FileName = $opensslPath 
$in.StartInfo.UseShellExecute = $false

$out = [System.Diagnostics.Process]::new()
$out.StartInfo.Arguments = "pkcs12 -export -passout pass:"
$out.StartInfo.FileName = $opensslPath
$out.StartInfo.UseShellExecute = $false;

$in.StartInfo.RedirectStandardOutput = $true
$in.StartInfo.RedirectStandardError = $true
$out.StartInfo.RedirectStandardInput = $true
$out.StartInfo.RedirectStandardOutput = $true

[void]$in.Start()
[void]$out.Start()


$in.StandardOutput.BaseStream.CopyTo($out.StandardInput.BaseStream)
$out.StandardInput.Dispose()
$ms = [System.IO.MemoryStream]::new()
$out.StandardOutput.BaseStream.CopyTo($ms)

$out.StandardOutput.Dispose()
$ms.Dispose()

# -------- end

$bytes = $ms.ToArray()

if($AsBase64) {
  return [System.Convert]::ToBase64String($bytes)
} else {
  return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes))
}

}


# ------------------ 

function New-OpenSSlX509Pem { param(
  [Parameter(Mandatory=$true, Position=0)][String]$CommonName,
  [Int]$KeySize = 4096,
  [Int]$Days = 365,
  [String]$OpenSslPath,
  [Switch]$AsCmsRecipient
  
)

if(!$OpenSslPath){
 
 $srcPath = (Get-Command -Name openssl -ErrorAction SilentlyContinue).Source
 $gitPath = [System.IO.FileInfo]"C:\Program Files\Git\mingw64\bin\openssl.exe"
 $aliasPath = (Get-Alias -Name openssl -ErrorAction SilentlyContinue).Definition

 $OpenSslPath = If($srcPath) { $srcPath }
 elseif($gitPath.Exists){ $gitPath.FullName }
 elseif($aliasPath) {$aliasPath}
 else {Throw "Can't locate openssl executable. Use OpenSslPathParameter to specify the location"} 
  
}

$OpenSslVersion = &$OpenSslPath "version"

if($AsCmsRecipient) {
if($OpenSslVersion -notlike '*1.1.1*') { Throw "cli extensions are not supported by this version ($OpenSslVersion). v1.1.1 is required"}
 $cmsExt = "-addext extendedKeyUsage=1.3.6.1.4.1.311.80.1 -addext keyUsage=keyEncipherment"
}

$in = [System.Diagnostics.Process]::new()
$in.StartInfo.Arguments = "req -x509 -sha256 -newkey rsa:$KeySize -keyout - -nodes -days $Days  -subj /CN=$CommonName  $cmsExt"
$in.StartInfo.FileName = $opensslPath 
$in.StartInfo.UseShellExecute = $false


$in.StartInfo.RedirectStandardOutput = $true
$in.StartInfo.RedirectStandardError = $true

[void]$in.Start()

return $in.StandardOutput.ReadToEnd()


}



Export-ModuleMember -Function New-OpenSslPfx, New-OpenSslX509Pem 