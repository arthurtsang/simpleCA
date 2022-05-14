package com.youramaryllis.simpleca;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Paths;

@Component
@Slf4j
public class CertCABuilder {
    @Autowired
    SimpleCertAuthConfiguration configuration;
    @Autowired
    CertAuthority certAuthority;
    @Value("${server.port}")
    int serverPort;

    @SneakyThrows
    @PostConstruct
    public void buildCA() {
        Files.createDirectories(Paths.get(configuration.caPath));
        CA rootca = configuration.rootca;
        rootca.name = "rootca";
        buildCA(null, rootca);
    }

    public void buildCA(CA parent, CA ca) {
        log.info("building {}", ca.name);
        if (ca.password == null) {
            ca.password = configuration.defaultPassword;
        }
        ca.host = configuration.hostname;
        ca.port = serverPort;
        ca.ocspPort = configuration.ocspPort;
        ca.signingCA = parent;
        if (configuration.recreate) certAuthority.cleanUp(ca);
        boolean keyCreated = certAuthority.generatePrivateKey(ca);
        boolean certCreated;
        if (parent == null) {
            certCreated = certAuthority.generateCert(ca, keyCreated); // force regenerate cert if key is newly created
            certAuthority.generateTrustStore(ca, certCreated); // only root ca need truststore and regenerate if cert is updated
        } else {
            ca.signingCAName = parent.name;
            boolean csrCreated = certAuthority.generateCSR(ca, keyCreated);
            certCreated = certAuthority.signCert(ca, csrCreated);
        }
        certAuthority.createIndexFiles(ca, certCreated); // reset indices if cert is newly created
        certAuthority.generateCAConfig(ca); // recreate the ca.conf regardless if any cert/key changes, it's driven by the application.yaml changes
        certAuthority.generateCrl(ca, certCreated);
        certAuthority.generateChainCert(ca, certCreated);
        certAuthority.generateOCSPPrivateKey(ca);
        certAuthority.generateOCSPCert(ca);
        for (CA child : ca.ca) {
            buildCA(ca, child);
        }
        for (Cert cert : ca.certs) {
            buildCert(ca, cert);
        }
    }

    public void buildCert(CA ca, Cert cert) {
        if (cert.password == null) cert.password = configuration.defaultPassword;
        cert.signingCA = ca;
        boolean keyCreated = certAuthority.generatePrivateKey(cert);
        boolean csrCreated = certAuthority.generateCSR(cert, keyCreated);
        certAuthority.signCert(cert, csrCreated);
        certAuthority.copyChainCert(ca, cert, csrCreated);
        if (cert.revoked) certAuthority.revokeCert(ca, cert);
        certAuthority.verifyCert(ca, cert);
        certAuthority.generateKeyStore(cert, csrCreated);
        certAuthority.copyTrustStore(cert);
    }
}
