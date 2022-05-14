[ ca ]
default_ca = myca

[ crl_ext ]
issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

 [ myca ]
 dir = ./
 new_certs_dir = \$dir
 unique_subject = no
 certificate = \$dir/${name}.crt
 database = \$dir/certindex
 private_key = \$dir/${name}.key
 serial = \$dir/certserial
 default_days = 365
 default_md = sha256
 policy = myca_policy
 x509_extensions = myca_extensions
 crlnumber = \$dir/crlnumber
 default_crl_days = 365

 [ myca_policy ]
 commonName = supplied
 stateOrProvinceName = supplied
 countryName = optional
 emailAddress = optional
 organizationName = supplied
 organizationalUnitName = optional

 [ myca_extensions ]
 basicConstraints = ${basicConstraints}
 keyUsage = critical,any
 subjectKeyIdentifier = hash
 authorityKeyIdentifier = keyid:always,issuer
 keyUsage = ${keyUsage}
 extendedKeyUsage = ${extendedKeyUsage}
 crlDistributionPoints = @crl_section
 authorityInfoAccess = @ocsp_section
 ${subjectAltName}

 ${alt_names}

 [crl_section]
 URI.0 = http://${host}:${port}/ca/${path}/${name}.crl

 [ocsp_section]
 caIssuers;URI.0 = http://${host}:${port}/ca/${path}/${name}.crt
 OCSP;URI.0 = http://${host}:${ocspPort}/