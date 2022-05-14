package com.youramaryllis.simpleca;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "simpleca")
@Data
public class SimpleCertAuthConfiguration {
    String hostname;
    String caPath;
    String opensslPath;
    String defaultPassword;
    CA rootca;
    boolean recreate;
    int ocspPort;
}

interface CertCA {
    String getName();

    String getPassword();

    int getKeySize();

    String getRelativePath();

    String getSubject();

    CA getSigningCA();
}

@Data
@ToString
class CA implements CertCA, Cloneable {
    @JsonProperty(index = 1)
    String name;
    @JsonProperty(index = 2)
    int keySize;
    @JsonProperty(index = 3)
    int days;
    @JsonProperty(index = 4)
    String subject;
    @JsonProperty(index = 5)
    String relativePath;
    @JsonProperty(index = 6)
    Integer pathLenConstraint;
    @JsonProperty(index = 7)
    Boolean caConstraint;
    @JsonProperty(index = 8)
    boolean clientAuth;
    @JsonProperty(index = 9)
    String keyUsage;

    @JsonProperty(index = 10)
    String password;
    @JsonProperty(index = 11)
    String signingCAName;

    @JsonProperty(index = 12)
    List<String> subjectAltName = new ArrayList<>();
    @JsonProperty(index = 50)
    List<Cert> certs = new ArrayList<>();
    @JsonProperty(index = 60)
    List<CA> ca = new ArrayList<>();

    @JsonIgnore
    String host;
    @JsonIgnore
    Integer port;
    @JsonIgnore
    Integer ocspPort;
    @JsonIgnore
    @ToString.Exclude
    CA signingCA;

    public Map<String, Object> toCAConfigMap() {
        StringBuilder basicConstraints = new StringBuilder();
        basicConstraints.append("critical");
        if (caConstraint)
            basicConstraints.append(",CA:TRUE");
        else
            basicConstraints.append(",CA:FALSE");
        if (pathLenConstraint != null)
            basicConstraints.append(",pathlen:").append(pathLenConstraint);
        StringBuilder extendedKeyUsage = new StringBuilder();
        extendedKeyUsage.append("serverAuth");
        if (clientAuth) extendedKeyUsage.append(",clientAuth");
        StringBuilder altNames = new StringBuilder();
        if (subjectAltName.size() > 0) altNames.append("[alt_names]\n");
        for (String altName : subjectAltName) {
            altNames.append(" ").append(altName).append("\n");
        }
        return new HashMap<>(Map.of(
                "name", name,
                "host", host,
                "port", port,
                "ocspPort", ocspPort,
                "path", relativePath,
                "subjectAltName", (subjectAltName.size() == 0) ? "" : "subjectAltName = @alt_names",
                "alt_names", altNames,
                "keyUsage", (keyUsage == null) ? "" : keyUsage,
                "extendedKeyUsage", extendedKeyUsage.toString(),
                "basicConstraints", basicConstraints.toString()
        ));
    }

    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}

@Data
@ToString
class Cert implements CertCA {
    String name;
    int keySize;
    String subject;
    String password;
    boolean revoked;
    String relativePath;
    @JsonIgnore
    @ToString.Exclude
    CA signingCA;
}