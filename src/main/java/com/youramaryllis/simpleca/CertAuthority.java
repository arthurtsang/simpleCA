package com.youramaryllis.simpleca;

import groovy.text.SimpleTemplateEngine;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.ResourceUtils;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;
import org.zeroturnaround.exec.stream.slf4j.Slf4jStream;

import javax.annotation.PostConstruct;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/* TODO: make into a prototype bean for each CA */

@Component
@Slf4j
public class CertAuthority {

    @Autowired
    SimpleTemplateEngine simpleTemplateEngine;
    @Autowired
    SimpleCertAuthConfiguration configuration;
    @Autowired
    ResourceLoader resourceLoader;

    Path basePath;
    String opensslBin;

    @PostConstruct
    public void setup() {
        basePath = Paths.get(configuration.caPath).normalize().toAbsolutePath();
        opensslBin = Paths.get(configuration.opensslPath).resolve("openssl").toString();
    }

    @SneakyThrows
    public void cleanUp(CA ca) {
        Path workingDirectory = basePath.resolve(ca.relativePath);
        Files.walk(workingDirectory)
                .filter(Files::isRegularFile)
                .filter(file -> !file.toString().endsWith(".key"))
                .map(Path::toFile)
                .peek(file -> log.info("deleting " + file.toString()))
                .forEach(File::delete);
    }

    //openssl genrsa -aes256 -passout pass:changeit -out rootca.key 8192
    public boolean generatePrivateKey(CertCA certCA) {
        assert Objects.nonNull(certCA.getPassword());
        List<String> cmd = List.of(
                opensslBin,
                "genrsa", "-aes256",
                "-passout", "pass:" + certCA.getPassword(),
                "-out", certCA.getName() + ".key",
                String.valueOf(certCA.getKeySize())
        );
        return executeAndExpectOutputFile(certCA, cmd, certCA.getName() + ".key");
    }

    //openssl req -sha256 -new -x509 -days 1826 -key rootca.key -out rootca.crt -subj '/C=US/ST=California/L=San Francisco/O=Test/CN=Root CA' -passin pass:changeit
    public boolean generateCert(CA ca, boolean forceRecreate) {
        assert Objects.nonNull(ca.password);
        if (forceRecreate) deleteOldFiles(ca, ca.name + ".crt");
        List<String> cmd = List.of(
                opensslBin,
                "req", "-sha256", "-new", "-x509",
                "-days", String.valueOf(ca.days),
                "-key", ca.name + ".key",
                "-out", ca.name + ".crt",
                "-subj", ca.subject,
                "-passin", "pass:" + ca.password
        );
        return executeAndExpectOutputFile(ca, cmd, ca.name + ".crt");
    }

    /*
    rm -f certindex* certserial* crlnumber*
    touch certindex
    echo 1000 > certserial
    echo 1000 > crlnumber
     */
    public void createIndexFiles(CA ca, boolean forceRecreate) {
        Path workingDirectory = getWorkingDirectory(ca);
        createIndexFile("certindex", ca, workingDirectory, null, forceRecreate);
        createIndexFile("certserial", ca, workingDirectory, "1000", forceRecreate);
        createIndexFile("crlnumber", ca, workingDirectory, "1000", forceRecreate);
    }

    @SneakyThrows
    private void createIndexFile(String name, CA ca, Path workingDirectory, String initialContent, boolean forceRecreate) {
        Path indexfile = workingDirectory.resolve(name);
        if (forceRecreate)
            deleteOldFiles(ca, name, name + ".old", name + ".attr");
        if (Files.notExists(indexfile)) {
            Files.createFile(indexfile);
            if (initialContent != null) Files.writeString(indexfile, initialContent);
            log.info("{} for {} created", name, ca.name);
        } else {
            log.info("{} for {} already existed", name, ca.name);
        }
    }

    @SneakyThrows
    public void generateCAConfig(CA ca) {
        Path workingDirectory = getWorkingDirectory(ca);
        Path caconfigFile = workingDirectory.resolve("ca.conf");
        if (Files.exists(caconfigFile))
            log.info("ca.conf for {} already existed, regenerate it anyway", ca.name);
        Resource templateResource = (ca.signingCA == null) ? //root CA don't have signing CA
                resourceLoader.getResource("classpath:templates/rootca.conf.tpl") :
                resourceLoader.getResource("classpath:templates/intermediateca.conf.tpl");
        ByteArrayOutputStream template = new ByteArrayOutputStream();
        templateResource.getInputStream().transferTo(template);
        String caconfig = simpleTemplateEngine.createTemplate(template.toString()).make(ca.toCAConfigMap()).toString();
        Files.writeString(caconfigFile, caconfig);
        log.info("ca.conf for {} created", ca.name);
    }

    //openssl req -sha256 -new -key intermediate.key -out intermediate.csr -subj '/C=US/ST=California/L=San Francisco/O=Test/CN=Intermediate CA' -passin pass:changeit
    public boolean generateCSR(CertCA certCA, boolean forceRecreate) {
        assert Objects.nonNull(certCA.getPassword());
        if (forceRecreate)
            deleteOldFiles(certCA, certCA.getName() + ".csr");
        List<String> cmd = List.of(
                opensslBin,
                "req", "-sha256", "-new",
                "-key", certCA.getName() + ".key",
                "-out", certCA.getName() + ".csr",
                "-subj", certCA.getSubject(),
                "-passin", "pass:" + certCA.getPassword()
        );
        return executeAndExpectOutputFile(certCA, cmd, certCA.getName() + ".csr");
    }

    //openssl ca -batch -config ca.conf -notext -in intermediate.csr -out intermediate.crt -passin pass:changeit
    @SneakyThrows
    public boolean signCert(CertCA certCA, boolean forceRecreate) {
        CA parent = certCA.getSigningCA();
        assert Objects.nonNull(certCA.getPassword());
        Path workingDirectory = getWorkingDirectory(parent);
        Path certsDirectory = workingDirectory.resolve("certs");
        Files.createDirectories(certsDirectory);
        Path certFilename = certsDirectory.resolve(certCA.getName() + ".crt");
        Path caWorkingDirectory = getWorkingDirectory(certCA);
        Path caCertFilename = caWorkingDirectory.resolve(certCA.getName() + ".crt");
        if (forceRecreate) {
            Files.deleteIfExists(certFilename);
            Files.deleteIfExists(caCertFilename);
        }
        List<String> cmd = List.of(
                opensslBin,
                "ca", "-batch",
                "-config", "ca.conf",
                "-notext",
                "-in", caWorkingDirectory.resolve(certCA.getName() + ".csr").toString(),
                "-out", certFilename.toString(),
                "-passin", "pass:" + certCA.getPassword()
        );
        boolean result = executeAndExpectOutputFile(parent, cmd, "certs/" + certCA.getName() + ".crt");
        FileCopyUtils.copy(certFilename.toFile(), caCertFilename.toFile());
        return result;
    }

    /*
    openssl ca -config ca.conf -gencrl -keyfile rootca.key -cert rootca.crt -out rootca.crl.pem -passin pass:changeit
    openssl crl -inform PEM -in rootca.crl.pem -outform DER -out rootca.crl
     */
    public boolean generateCrl(CA ca, boolean forceRecreate) {
        assert Objects.nonNull(ca.password);
        if (forceRecreate) deleteOldFiles(ca, ca.name + ".crl.pem", ca.name + ".crl");
        List<String> cmd = List.of(
                opensslBin, "ca",
                "-config", "ca.conf",
                "-gencrl",
                "-keyfile", ca.name + ".key",
                "-cert", ca.name + ".crt",
                "-out", ca.name + ".crl.pem",
                "-passin", "pass:" + ca.password
        );
        boolean result = executeAndExpectOutputFile(ca, cmd, ca.name + ".crl.pem");
        if (result) deleteOldFiles(ca, ca.name + ".crl");
        List<String> cmd2 = List.of(
                opensslBin, "crl",
                "-inform", "PEM",
                "-in", ca.name + ".crl.pem",
                "-outform", "DER",
                "-out", ca.name + ".crl"
        );
        return executeAndExpectOutputFile(ca, cmd2, ca.name + ".crl");
    }

    @SneakyThrows
    public void generateChainCert(CA ca, boolean forceRecreate) {
        CA parent = ca.signingCA;
        if (forceRecreate) deleteOldFiles(ca, "certs/chain.crt");
        Path chainCertDirectory = getWorkingDirectory(ca).resolve("certs");
        Files.createDirectories(chainCertDirectory);
        Path chainCertPath = chainCertDirectory.resolve("chain.crt");
        if (Files.notExists(chainCertPath)) {
            InputStream chainCertInputStream = Files.newInputStream(getWorkingDirectory(ca).resolve(ca.getName() + ".crt"));
            if (parent != null) {
                InputStream parentChainCertInputStream = Files.newInputStream(getWorkingDirectory(parent).resolve("certs").resolve("chain.crt"));
                chainCertInputStream = new SequenceInputStream(parentChainCertInputStream, chainCertInputStream);
            }
            OutputStream chainCertOutputStream = Files.newOutputStream(chainCertPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            chainCertInputStream.transferTo(chainCertOutputStream);
            chainCertOutputStream.flush();
            chainCertOutputStream.close();
            assert Files.exists(chainCertPath);
        }
        generateCrlChainCert(ca, forceRecreate);
    }

    @SneakyThrows
    public void generateCrlChainCert(CA ca, boolean forceRecreate) {
        Path chainCertDirectory = getWorkingDirectory(ca).resolve("certs");
        Path chainCertPath = chainCertDirectory.resolve("chain.crt");
        Path crlChainCertPath = chainCertDirectory.resolve("crl-chain.crt");
        if (forceRecreate) deleteOldFiles(ca, "certs/crl-chain.crt");
        if (Files.notExists(crlChainCertPath)) {
            OutputStream crlChainCertOutputStream = Files.newOutputStream(crlChainCertPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            InputStream chainCertInputStream = Files.newInputStream(chainCertPath);
            InputStream parentCrlCertInputStream = Files.newInputStream(getWorkingDirectory(ca).resolve(ca.name + ".crl.pem"));
            chainCertInputStream = new SequenceInputStream(parentCrlCertInputStream, chainCertInputStream);
            chainCertInputStream.transferTo(crlChainCertOutputStream);
            crlChainCertOutputStream.flush();
            crlChainCertOutputStream.close();
            assert Files.exists(crlChainCertPath);
        }
    }

    //openssl verify -CAfile chain.crt server.crt
    @SneakyThrows
    public void verifyCert(CA ca, Cert cert) {
        Path certPath = getWorkingDirectory(cert).resolve(cert.name + ".crt");
        assert Files.exists(certPath);
        Path chainCertPath = getWorkingDirectory(ca).resolve("certs").resolve("chain.crt");
        assert Files.exists(chainCertPath);
        List<String> cmd = List.of(
                opensslBin, "verify",
                "-CAfile", chainCertPath.toString(),
                certPath.toString()
        );
        execute(cert, cmd);
    }

    //openssl ca -config ca.conf -revoke client2.crt -keyfile intermediate.key -cert intermediate.crt -passin pass:changeit
    @SneakyThrows
    public void revokeCert(CA ca, Cert cert) {
        if (isCertRevoked(ca, cert)) {
            log.info(cert.name + " is already revoked");
            return;
        }
        assert Objects.nonNull(ca.password);
        Path workingDirectory = getWorkingDirectory(ca);
        Path certDirectory = getWorkingDirectory(cert);
        List<String> cmd = List.of(
                opensslBin, "ca",
                "-config", workingDirectory.resolve("ca.conf").toString(),
                "-revoke", certDirectory.resolve(cert.name + ".crt").toString(),
                "-keyfile", workingDirectory.resolve(ca.name + ".key").toString(),
                "-cert", workingDirectory.resolve(ca.name + ".crt").toString(),
                "-passin", "pass:" + ca.password
        );
        execute(ca, cmd);
        log.info(cert.name + " revoked");
        generateCrl(ca, true);
        generateCrlChainCert(ca, true);
    }

    //openssl verify -crl_check -CAfile crl-chain.crt client2.crt
    public boolean isCertRevoked(CA ca, Cert cert) {
        Path workingDirectory = getWorkingDirectory(ca);
        Path certDirectory = getWorkingDirectory(cert);
        List<String> cmd = List.of(
                opensslBin, "verify", "-crl_check",
                "-CAfile", workingDirectory.resolve("certs").resolve("crl-chain.crt").toString(),
                certDirectory.resolve(cert.name + ".crt").toString()
        );
        try {
            execute(ca, cmd);
        } catch (AssertionError ae) {
            return true;
        }
        return false;
    }

    @SneakyThrows
    public void copyChainCert(CA ca, Cert cert, boolean forceRecreate) {
        if (forceRecreate) deleteOldFiles(cert, "chain.crt");
        Path from = getWorkingDirectory(ca).resolve("certs").resolve("chain.crt");
        Path to = getWorkingDirectory(cert).resolve("chain.crt");
        if (Files.notExists(to))
            Files.newInputStream(from).transferTo(Files.newOutputStream(to));
    }

    //openssl pkcs12 -export -out client-keystore.p12 -inkey client.key -in client.crt -certfile chain.crt -passin pass:changeit -passout pass:changeit
    public void generateKeyStore(Cert cert, boolean forceRecreate) {
        assert Objects.nonNull(cert.password);
        if (forceRecreate) deleteOldFiles(cert, "keystore.p12");
        List<String> cmd = List.of(
                opensslBin, "pkcs12", "-export",
                "-out", "keystore.p12",
                "-inkey", cert.name + ".key",
                "-in", cert.name + ".crt",
                "-certfile", "chain.crt",
                "-passin", "pass:" + cert.password,
                "-passout", "pass:" + cert.password
        );
        executeAndExpectOutputFile(cert, cmd, "keystore.p12");
    }

    //keytool -importcert -alias ca -file ../rootca/rootca.crt -keystore truststore.p12 -storepass:file changeit -noprompt
    @SneakyThrows
    public void generateTrustStore(CA ca, boolean forceRecreate) {
        assert Objects.nonNull(ca.password);
        Path workingDirectory = getWorkingDirectory(ca);
        Files.createDirectories(workingDirectory.resolve("certs"));
        if (forceRecreate) deleteOldFiles(ca, "certs/truststore.p12");
        Path storepass = workingDirectory.resolve("storepass");
        Files.writeString(storepass, ca.password);
        List<String> cmd = List.of(
                "keytool", "-importcert",
                "-alias", "ca",
                "-file", ca.name + ".crt",
                "-keystore", "certs/truststore.p12",
                "-storepass:file", "storepass",
                "-noprompt"
        );
        executeAndExpectOutputFile(ca, cmd, "certs/truststore.p12");
        Files.deleteIfExists(storepass);
    }

    @SneakyThrows
    public void copyTrustStore(Cert cert) {
        CA rootCA = cert.signingCA;
        while (rootCA.signingCA != null) {
            rootCA = rootCA.signingCA;
        }
        Path from = getWorkingDirectory(rootCA).resolve("certs").resolve("truststore.p12");
        Path to = getWorkingDirectory(cert).resolve("truststore.p12");
        assert Files.exists(from);
        Files.newInputStream(from).transferTo(Files.newOutputStream(to));
        log.info(to + " created");
    }

    @SneakyThrows
    public void deleteOldFiles(CertCA certCA, String... names) {
        Path workingDirectory = getWorkingDirectory(certCA);
        for (String filename : names) {
            Path filePath = workingDirectory.resolve(filename);
            boolean isDeleted = Files.deleteIfExists(filePath);
            if (isDeleted) log.info(filePath.toString() + " is deleted");
        }
    }

    //openssl req -new -nodes -out ocspSigning.csr -keyout ocspSigning.key
    public boolean generateOCSPPrivateKey(CA ca) {
        assert Objects.nonNull(ca.getPassword());
        String subject = Arrays.stream(ca.subject.split("/")).map(s -> (s.startsWith("CN=")) ? "CN=" + ca.name + " OCSP" : s).collect(Collectors.joining("/"));
        List<String> cmd = List.of(
                opensslBin,
                "req", "-new", "-nodes",
                "-subj", subject,
                "-out", ca.getName() + "-ocsp-signer.csr",
                "-keyout", ca.getName() + "-ocsp-signer.key"
        );
        return executeAndExpectOutputFile(ca, cmd, ca.getName() + "-ocsp-signer.key", ca.getName() + "-ocsp-signer.csr");
    }

    //openssl ca -batch -keyfile rootCA.key -cert rootCA.crt -in ocspSigning.csr -out ocspSigning.crt -config validation.conf
    public boolean generateOCSPCert(CA ca) {
        assert Objects.nonNull(ca.getPassword());
        List<String> cmd = List.of(
                opensslBin, "ca", "-batch",
                "-keyfile", ca.name + ".key",
                "-cert", ca.name + ".crt",
                "-in", ca.name + "-ocsp-signer.csr",
                "-out", ca.name + "-ocsp-signer.crt",
                "-passin", "pass:" + ca.password,
                "-config", "ca.conf"
        );
        return executeAndExpectOutputFile(ca, cmd, ca.getName() + "-ocsp-signer.crt");
    }

    public Runnable startOCSP(List<CA> allCA) {
        List<String> cmd = allCA.stream()
                .flatMap(ca -> {
                    Path caDirectory = getWorkingDirectory(ca);
                    return List.of(
                            "-index", caDirectory.resolve("certindex").toString(),
                            "-CA", caDirectory.resolve(ca.name + ".crt").toString(),
                            "-rsigner", caDirectory.resolve(ca.name + "-ocsp-signer.crt").toString(),
                            "-rkey", caDirectory.resolve(ca.name + "-ocsp-signer.key").toString()
                    ).stream();
                }).collect(Collectors.toList());
        cmd.add(0, opensslBin);
        cmd.add(1, "ocsp");
        cmd.add("-port");
        cmd.add(String.valueOf(configuration.getOcspPort()));
        cmd.add("-text");
        return () -> executeNoTimeout(cmd);
    }

    @SneakyThrows
    private Path getWorkingDirectory(CertCA certCA) {
        Path workingDirectory = basePath.resolve(certCA.getRelativePath());
        Files.createDirectories(workingDirectory);
        return workingDirectory;
    }

    @SneakyThrows
    private boolean executeAndExpectOutputFile(CertCA certCA, List<String> cmd, String... outputName) {
        Path workingDirectory = getWorkingDirectory(certCA);
        Optional<Path> anyMissing = Arrays.stream(outputName)
                .map(workingDirectory::resolve)
                .filter(Files::notExists)
                .findAny();
        if (anyMissing.isPresent()) {
            OutputStream error = new ByteArrayOutputStream();
            ProcessResult result = new ProcessExecutor().command(cmd)
                    .directory(workingDirectory.toFile())
                    .redirectOutput(Slf4jStream.ofCaller().asTrace())
                    .redirectError(error)
                    .execute();
            String errorMsg = error.toString();
            if (Strings.isNotEmpty(errorMsg)) {
                log.info(errorMsg);
            }
            assert result.getExitValue() == 0 : error.toString();
            List<Path> fileMissing = Arrays.stream(outputName)
                    .map(workingDirectory::resolve)
                    .filter(Files::notExists)
                    .collect(Collectors.toList());
            assert fileMissing.size() == 0 : "files are missing: " + fileMissing;
            log.info(String.join(",", outputName) + " file(s) created");
            return true;
        } else {
            log.info(String.join(",", outputName) + " already existed");
            return false;
        }
    }

    @SneakyThrows
    private void execute(CertCA certCA, List<String> cmd) {
        Path workingDirectory = getWorkingDirectory(certCA);
        OutputStream error = new ByteArrayOutputStream();
        ProcessResult result = new ProcessExecutor().command(cmd)
                .directory(workingDirectory.toFile())
                .redirectOutput(Slf4jStream.ofCaller().asTrace())
                .redirectError(error)
                .execute();
        assert result.getExitValue() == 0 : error.toString();
    }

    @SneakyThrows
    private void executeNoTimeout(List<String> cmd) {
        Path workingDirectory = Paths.get(configuration.caPath);
        OutputStream error = new ByteArrayOutputStream();
        ProcessResult result = new ProcessExecutor().command(cmd)
                .directory(workingDirectory.toFile())
                .redirectOutput(Slf4jStream.ofCaller().asTrace())
                .redirectError(error)
                .executeNoTimeout();
        String errorMsg = error.toString();
        if (Strings.isNotEmpty(errorMsg))
            log.info(errorMsg);
        assert result.getExitValue() == 0 : error.toString();
    }
}
