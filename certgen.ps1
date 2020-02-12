@"
[ cms_ext ]
keyUsage=keyEncipherment
extendedKeyUsage=1.3.6.1.4.1.311.80.1
"@  | Out-File cms.cnf -Encoding default

openssl req -new -x509 -days 365 -keyout ca.key -out ca.cert -nodes -subj "/CN=CA"
openssl pkcs12 -export -out ca.pfx -inkey ca.key -in ca.cert  -passout "pass:123"

openssl req -new -sha256 -keyout server.key -out server.csr -nodes -subj "/CN=Server" 
openssl x509 -req -days 365 -in server.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out server.cert -extensions cms_ext -extfile cms.cnf
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.cert  -passout "pass:123"

openssl req -new -sha256 -keyout client.key -out client.csr -nodes -subj "/CN=Client"
openssl x509 -req -days 365 -in client.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out client.cert -extensions cms_ext -extfile cms.cnf
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.cert  -passout "pass:123"

Remove-Item *.csr
Remove-Item *.srl

$ca = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("ca.pfx", 123)
$server = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("server.pfx", 123)
$client = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("client.pfx", 123)


$cipher = "secret" | Protect-CmsMessage -to $server

$cipher | Unprotect-CmsMessage -to $server

