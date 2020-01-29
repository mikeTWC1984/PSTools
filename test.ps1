
using namespace System.Security.Cryptography.X509Certificates

Import-Module .\Cert.psm1

$c1 = New-SelfSignedCertificate2 "user1" -KeyUsage DataEncipherment -EKU DocumentEncryption
$c2 = New-SelfSignedCertificate2 "user 2" -KeyUsage DataEncipherment -EKU DocumentEncryption


$my = [X509Store]::new("my", "CurrentUser")
$lm = [X509Store]::new("my", "LocalMachine")

$my.Open("ReadWrite")
$lm.Open("ReadWrite")


$my.Add($c1)
$my.Add($c2)
$lm.Add($c1)
$my.Remove($c1)
$lm.Remove($c1)