package com.youramaryllis.simpleca;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

@Slf4j
@RestController
@RequestMapping("/api")
public class CertAuthController {

    @Autowired
    CertAuthDatabase database;
    @Autowired
    CertCABuilder certCABuilder;
    @Autowired
    SimpleCertAuthConfiguration configuration;

    @GetMapping(value = "/ca", produces = MediaType.APPLICATION_JSON_VALUE)
    public Flux<CA> getAllCA() {
        return Flux.fromIterable(database.getAllCleanCA());
    }

    @GetMapping(value = "/ca/{name}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<CA> getCA(@PathVariable String name) {
        try {
            CA ca = database.getCleanCA(name);
            assert Objects.nonNull(ca);
            return Mono.just(ca);
        } catch (Throwable throwable) {
            return Mono.error(throwable);
        }
    }

    @PostMapping(value = "/ca/{signingCaName}",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<Void> createCA(@PathVariable String signingCaName, @RequestBody CA ca) {
        if (ca.relativePath == null) ca.relativePath = ca.name;
        try {
            assert ca.ca.size() == 0;
            assert ca.certs.size() == 0;
            CA signingCA = database.getCA(signingCaName);
            assert Objects.nonNull(signingCA);
            ca.signingCAName = signingCA.name;
            ca.signingCA = signingCA;
            certCABuilder.buildCA(signingCA, ca);
            database.addCA(signingCA, ca);
            database.flush();
        } catch (Throwable throwable) {
            return Mono.error(throwable);
        }
        return Mono.empty();
    }

    @PostMapping(value = "/cert/{signingCaName}",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public Mono<Void> createCert(@PathVariable String signingCaName, @RequestBody Cert cert) {
        try {
            if (cert.relativePath == null) cert.relativePath = cert.name;
            cert.signingCA = database.getCA(signingCaName);
            assert Objects.nonNull(cert.signingCA);
            certCABuilder.buildCert(cert.signingCA, cert);
            database.addCert(cert.signingCA, cert);
            database.flush();
        } catch (Throwable e) {
            return Mono.error(e);
        }
        return Mono.empty();
    }

    @DeleteMapping(value = "/cert/{signingCA}/{certName}")
    public Mono<Void> revokeCert(@PathVariable String signingCA, @PathVariable String certName) {
        try {
            CA ca = database.getCA(signingCA);
            assert Objects.nonNull(ca);
            Cert cert = ca.certs.stream().filter(c->c.name.equals(certName)).findFirst().orElseThrow(()->new AssertionError("Cert name " + certName + " not found in CA " + signingCA ));
            cert.revoked = true;
            certCABuilder.buildCert(ca, cert);
            database.flush();
        } catch (Throwable t) {
            return Mono.error(t);
        }
        return Mono.empty();
    }

    @SneakyThrows
    @GetMapping(value = "/cert/{caName}/keystore")
    @ResponseBody
    public ResponseEntity<Mono<Resource>> getKeystore(@PathVariable String caName) {
        Path keyStoreFile = Paths.get(configuration.caPath).resolve(caName).resolve("keystore.p12");
        if (Files.notExists(keyStoreFile))
            return ResponseEntity.notFound().build();
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=keystore.p12")
                .body(
                        Mono.just(new InputStreamResource(Files.newInputStream(keyStoreFile)))
                );
    }

    @SneakyThrows
    @GetMapping(value = "/cert/{caName}/truststore")
    @ResponseBody
    public ResponseEntity<Mono<Resource>> getTruststore(@PathVariable String caName) {
        Path trustStoreFile = Paths.get(configuration.caPath).resolve(caName).resolve("truststore.p12");
        if (Files.notExists(trustStoreFile))
            return ResponseEntity.notFound().build();
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=truststore.p12")
                .body(
                        Mono.just(new InputStreamResource(Files.newInputStream(trustStoreFile)))
                );
    }

    @ExceptionHandler(AssertionError.class)
    ResponseEntity assertionError(AssertionError assertionError) {
        log.info("handling assertion error {}", assertionError.getMessage());
        return ResponseEntity.badRequest().body(assertionError.getMessage());
    }

    @ExceptionHandler(Throwable.class)
    ResponseEntity otherError(Throwable throwable) {
        log.info("handling throwable", throwable);
        return ResponseEntity.badRequest().body(throwable.getMessage());
    }
}
