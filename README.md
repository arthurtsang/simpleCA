# SimpleCA

## Overview

Intended for development to quickly setup a CA, with CRL and OCSP responder to test TLS/SSL setup.

OpenSSL is great, but to create an environment for a multi-level CA to sign a few certs and revoke them requires a lot of commands and knowledge.
This project tries to encapsulate most of the complexity by calling the OpenSSL commands behind a few simple API.

## Features
2. generate root cert (auto during first start)
3. generate intermediate CA (to sign leave cert or another intermediate?  client auth?)
4. generate leave cert (client auth? localhost?)
5. serve CRL
6. start ocsp with openssl
7. download keystore and trust store
8. use json editor for UI? (Not yet done)

## Directory Structure

```
/simpleca
  /rootca
    ca.conf
    rootca.crl
    /certs
      inter1.crt
  /inter1
    ca.conf
    inter1.crl
    /certs
      inter2.crt
  /inter2
    ca.conf
    inter2.crl
    /certs
      server.crt
      client.crt
  /server
    server.crt
  /client
    client.crt
```

## Configuration

* application.yaml
```yaml
server:
  port: 4000
simpleca:
  hostname: localhost
  caPath: ./myca
  opensslPath: /usr/bin
  defaultPassword: changeit
  recreate: false
  ocspPort: 5000
```

The default application.yaml is embedded in the jar file, all values can be overridden with normal [Spring Boot Externalized Configuration](https://docs.spring.io/spring-boot/docs/2.1.8.RELEASE/reference/html/boot-features-external-config.html)

* example.yaml

```yaml
simpleca:
  rootca:
    relativePath: rootca
    keySize: 2048
    days: 1826
    pathLenConstraint: 2
    caConstraint: true
    subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=Root CA
    ca:
      - name: inter1
        relativePath: inter1
        keysize: 2048
        days: 1826
        subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=Inter1 CA
        caConstraint: true
        keyUsage: digitalSignature,keyEncipherment,cRLSign,keyCertSign
        ca:
          - name: inter1a
            relativePath: inter1a
            keySize: 8192
            days: 1826
            caConstraint: false
            clientAuth: true
            subjectAltName:
              - DNS.0 = localhost
              - IP.0 = 127.0.0.1
            subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=Inter1a CA
            keyUsage: digitalSignature,keyEncipherment
            certs:
              - name: server
                keySize: 2048
                subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=server
                relativePath: server
              - name: client1
                keySize: 2048
                subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=client1
                relativePath: client1
              - name: client2
                keySize: 2048
                subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=client2
                revoked: true
                relativePath: client2
      - name: inter2
        relativePath: inter2
        keysize: 2048
        days: 1826
        subject: /C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=Inter2 CA
        caConstraint: false
        keyUsage: digitalSignature,keyEncipherment

```

The above is an example of structure of the CA and certificates.
It is passed into the application with
```shell
--spring.location.config=classpath:/application.yaml,./src/test/resources/example.yaml
```
Thus, everytime the server starts up, it will make sure all files are there (you might have to download the keystore/truststore if they are regenerated).

To add a CA or generate a certificate, you can manually edit this file and restart the server or call the API.

## API

- `GET /api/ca` - return a list of all CA
- `GET /api/ca/{name}` - return details of the named CA
- `POST /api/ca/{signingCaName}` - create a new CA and sign the cert with `signingCaName` CA
  - 
```json
{
  "name": "inter1b",
  "keySize": 8192,
  "days": 1826,
  "caConstraint": false,
  "clientAuth": true,
  "subject": "/C=US/ST=California/L=San Francisco/O=Youramaryllis/CN=Inter1b CA",
  "keyUsage": "digitalSignature,keyEncipherment"
}
```
- `POST /api/cert/{signingCaName}` - generate a certificate signed by the `signingCaName` CA
- `DELETE /api/cert/{signingCaName}/{certName}` - revoke a certificate
- `GET /api/cert/{caName}/keystore` - download keystore (it has the private key of the certificate and the chain certificates)
- `GET /api/cert/{caName}/truststore` - download truststore (it only contains the root CA cert)

## CRL

All CRL files are served `http://{host}:{port}/ca/{path}/{fileName}`,

| param | desc |
| --- | --- |
| host | host name as defined in application.yaml |
| port | port number as defined in application.yaml |
| path | relativePath,defined per CA |
| fileName | the crl filename, it's the name of the CA with `crl` as extension |

## OCSP

The caIssuers has the same format as CRL, except the extension is `crt`.
OCSP Responder is using `OpenSSL ocsp ... -port {ocspPort}` where ocspPort is defined in the application.yaml

## To Start the Server

run ```java -ea -jar simpleCA-1.0.0-SNAPSHOT.jar --spring.config.location=classpath:/application.yaml,../src/test/resources/example.yaml```
