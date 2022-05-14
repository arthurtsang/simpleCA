package com.youramaryllis.simpleca;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Slf4j
public class CertAuthDatabase {
    @Autowired
    SimpleCertAuthConfiguration configuration;
    @Autowired
    CertCABuilder certCABuilder; // just to make it run after certBuilder
    Database database = new Database();
    ObjectMapper mapper;
    @Value("${spring.config.location}")
    String location;
    String dbPath;
    Map<String, CA> caMap = new HashMap<>();

    @SneakyThrows
    @PostConstruct
    public void setup() {
        database.simpleCA.rootCA = configuration.rootca;
        mapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER));
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        dbPath = Arrays.stream(location.split(","))
                .filter(s -> !s.startsWith("classpath"))
                .findFirst()
                .orElse(Paths.get(".").resolve("simpleca.yaml").normalize().toString());
        addCA2MapRecursively(database.simpleCA.rootCA);
    }

    private void addCA2MapRecursively(CA ca) {
        caMap.put(ca.name, ca);
        for (CA downstreamCA : ca.ca) {
            addCA2MapRecursively(downstreamCA);
        }
    }

    public CA getCleanCA(String name) {
        CA ca = caMap.get(name);
        return cleanCA(ca);
    }

    @SneakyThrows
    private CA cleanCA(CA ca) {
        CA ca1 = (CA) ca.clone();
        ca1.ca = new ArrayList<>();
        ca1.certs = new ArrayList<>();
        ca1.password = null;
        ca1.relativePath = null;
        if (ca.signingCA != null) {
            ca1.signingCAName = ca.signingCA.name;
        }
        return ca1;
    }

    public CA getCA(String name) {
        return caMap.get(name);
    }

    public List<CA> getAllCA() {
        return new ArrayList<>(caMap.values());
    }

    public List<CA> getAllCleanCA() {
        return caMap.values().stream().map(this::cleanCA).collect(Collectors.toList());
    }

    public void addCA(CA signingCA, CA ca) {
        if (caMap.putIfAbsent(ca.name, ca) == null)
            signingCA.ca.add(ca);
    }

    public void addCert(CA ca, Cert cert) {
        if (ca.certs.stream().noneMatch(c -> c.name.equals(cert.name)))
            ca.certs.add(cert);
    }

    @SneakyThrows
    public void flush() {
        String yml = mapper.writeValueAsString(database);
        Files.deleteIfExists(Paths.get(dbPath));
        Files.writeString(Paths.get(dbPath), yml, StandardOpenOption.CREATE_NEW);
        log.info("Done flushing database file");
    }

}

@Data
class Database {
    @JsonProperty("simpleca")
    SimpleCA simpleCA = new SimpleCA();
}

@Data
class SimpleCA {
    @JsonProperty("rootca")
    CA rootCA;
}