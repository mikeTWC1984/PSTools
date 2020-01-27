
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


 Export-ModuleMember -Function "New-SelfSignedCertificate2"
