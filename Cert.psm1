
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Cryptography


Add-Type -TypeDefinition @"
using System.ComponentModel;
public enum EKU {
   None
  ,[Description("1.3.6.1.4.1.311.80.1")]DocumentEncryption
  ,[Description("1.3.6.1.5.5.7.3.1")]ServerAuthentication
  ,[Description("1.3.6.1.5.5.7.3.2")]ClientAuthentication
  ,[Description("1.3.6.1.5.5.7.3.3")]CodeSigning
  ,[Description("1.3.6.1.5.5.7.3.4")]SecureEmail
  ,[Description("1.3.6.1.5.5.7.3.8")]TimeStamping
}

"@


function New-SelfSignedCertificate2 { param(

     [Parameter(Mandatory=$true, Position=0)][String]$CommonName
    ,[Uint16]$KeyLength = 4096 #rsa only
    ,[Uint16]$Days = 365
    ,[ValidateSet("RSA","ECDSA")]$KeyAlg = "RSA"
    
    # extensions
    ,[X509KeyUsageFlags[]]$KeyUsage
    ,[EKU[]]$EKU
    ,[X509Extension[]]$OtherExtensions

    ,[Parameter(ParameterSetName="Ext")][switch]$AsRequest

    ,[X509Certificate2]$CACert
    
    ,[HashAlgorithmName]$HashAlg = [HashAlgorithmName]::SHA256
    ,[RSASignaturePadding]$RSAPadding = [RSASignaturePadding]::Pkcs1
    ,[datetime]$FromDate = [datetime]::UtcNow.AddDays(-1)

    ,[System.IO.FileInfo]$OutPfxFile # incl private key
    ,[String]$Passphrase
    ,[System.IO.FileInfo]$OutCertFile # public key only

    )

   $ErrorActionPreference = "STOP"
          
   $DN = [X500DistinguishedName]::new("CN="+ $CommonName.TrimStart("CN="))

   If($KeyAlg -eq "ECDSA"){
       if($KeyLength -notin 256, 384, 521) {$KeyLength = 521} 
       $keyPair = [ECDsa]::Create()
       $request = [CertificateRequest]::new($DN, $keyPair, $HashAlg)
     }
   Else{ 
       $keyPair = [RSA]::Create($KeyLength)
       $request = [CertificateRequest]::new($DN, $keyPair, $HashAlg, $RSAPadding)
     }


  # ------- set extensions

   If($EKU) {
      $oids = [OidCollection]::new()
      foreach($e in $EKU)
      { 
        $attr = [System.ComponentModel.DescriptionAttribute]
        $oid = [EKU].GetField($e).GetCustomAttributes($attr, $true)[0].Description
        if($oid){[void]$oids.Add([Oid]::new($oid))}
      }

      $enhExt = [X509EnhancedKeyUsageExtension]::new($oids,$false)
      $request.CertificateExtensions.Add($enhExt)
    }


   If($KeyUsage) {
        $request.CertificateExtensions.Add([X509KeyUsageExtension]::new($KeyUsage, $false))
     }

If($OtherExtensions) {
   foreach($ext in $OtherExtensions)
    { 
      $request.CertificateExtensions.Add($ext)
    }
 }


 # --------------------------------

  If($AsRequest) {return $request}
   
 # --------------------------------
 
   $certTmp = $request.CreateSelfSigned($FromDate, $FromDate.AddDays($Days))

   $certBytes = $certTmp.Export([X509ContentType]::Pfx, "tmp")

   [X509KeyStorageFlags[]]$flags = "PersistKeySet", "Exportable"

   $cert = [X509Certificate2]::new($certBytes, "tmp", $flags)

   
   if($OutPfxFile) { 
      if(!$Passphrase) { $Passphrase = Read-Host "Enter Passphrase: " -AsSecureString }
      [System.IO.File]::WriteAllBytes($OutPfxFile, $cert.Export([X509ContentType]::Pfx, $Passphrase))
    }
   
   if($OutCertFile) { 
     [System.IO.File]::WriteAllBytes($OutCertFile, $cert.Export([X509ContentType]::Cert))
    }

   return $cert 
 

 }


 # --------------------------

 function Protect-CmsMessage2 { param([Parameter(ValueFromPipeline=$true)][String]$Message, [X509Certificate2]$Cert) 

   $opt = [System.Base64FormattingOptions]::InsertLineBreaks
   $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($OutputEncoding.GetBytes($Message))
   $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new($contentInfo)
   $cms.Encrypt($cert) 
   $base64 =  [System.Convert]::ToBase64String($cms.Encode(), $opt )
   return "-----BEGIN CMS-----`n$base64`n-----END CMS-----"
}

function Unprotect-CmsMessage2 { param([Parameter(ValueFromPipeline=$true)]$Cipher, $Cert)
   $base64 = [regex]::Match($Cipher, 'CMS-----\n((?:.*\r?\n?)*)\n-----END').Groups[1].Value
   $cms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
   $cms.Decode([System.Convert]::FromBase64String($base64))
   if($Cert) {$cms.Decrypt($Cert)} Else {$cms.Decrypt()}
   return $OutputEncoding.GetString($cms.ContentInfo.Content)
}

function Import-PfxCertificate2 { param( 
    [Parameter(ValueFromPipeline=$true)][X509Certificate2]$Certificate
   ,[String]$FilePath, [String]$Password, [String]$CertStore="My"
   )

   If(!$Certificate) { $Certificate = [X509Certificate2]::new($FilePath, $Password, [X509KeyStorageFlags]::PersistKeySet) }
      
   $store = [X509Store]::new($CertStore)
   $store.Open("ReadWrite")
   $store.Add($Certificate)
   $store.Dispose()
   return $true
 }

function Export-PfxCertificate2 { param(
   [Parameter(ValueFromPipeline=$true)][X509Certificate2]$cert,
   [String]$FilePath, [String]$Password,[X509ContentType]$Type = "Pfx"
   )
   If(!$FilePath) { $FilePath = "$($cert.SerialNumber).pfx" }
   [System.IO.File]::WriteAllBytes($FilePath, $cert.Export($Type, "P@ssw0rd"))
}

 # kind of Get-ChildItem cert:\My
function Get-Certificate2 { param([String]$Thumbprint, [String]$Name="*", [String]$CertStore="My")
  $store = [X509Store]::new($CertStore); $store.Open("ReadOnly")
  $certList = If($Thumbprint) { $store.Certificates.Find("FindByThumbprint", $Thumbprint, $false)}
        Else {$store.Certificates | Where-Object { $_.Thumbprint -like $Name -OR $_.Subject -like $Name}}
  If( $certList.Count -eq 1) {return $certList[0] } Else {return $certList }
}
function Remove-Certificate2 { param(
   [Parameter(ValueFromPipeline=$true)][X509Certificate2]$Certificate, [String]$CertStore = "My"
)
  Begin { $store = [X509Store]::new("My"); $store.Open("ReadWrite") }
  Process { $store.Remove($Certificate) }
  End { $store.Dispose() }
 
}

<# ------------- TEST -------------

Get-Certificate -CertStore "My"

# in-memory cert
$cert = New-SelfSignedCertificate2 -Name "SamplePSCoreNix" -KeyLength 4096

# Encrypt/Decrypt
$cipher = Protect-CmsMessage2 -Message (irm www.example.com) -Cert $cert
$cipher | Unprotect-CmsMessage2 -Cert $cert

#export to file
$cert | Export-PfxCertificate2 -FilePath "SamplePSCoreNix.pfx" -Password "P@ssw0rd"

#  import to cert store
$cert | Import-PfxCertificate2 -CertStore "My"

# get cert from store
$cert = Get-Certificate -Name "*SamplePSCoreNix*" -CertStore "My"
$cipher | Unprotect-CmsMessage2  # once added to My store no need to specify cert

# Remove Cert from the store
$cert | Remove-Certificate -CertStore "My"

#>

 Export-ModuleMember -Function "New-SelfSignedCertificate2", Protect-CmsMessage2, Unprotect-CmsMessage2, Get-Certificate2, Remove-Certificate2, Import-PfxCertificate2 
