package com.youramaryllis.simpleca;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/ca")
public class CAController {
    @Autowired
    SimpleCertAuthConfiguration configuration;

    @SneakyThrows
    @GetMapping(value = "/{caName}/{fileName}")
    @ResponseBody
    public ResponseEntity<Mono<Resource>> getCrl(@PathVariable String caName, @PathVariable String fileName) {
        if( !fileName.endsWith(".crt") && !fileName.endsWith(".crl"))
            return ResponseEntity.notFound().build();
        Path file = Paths.get(configuration.caPath).resolve(caName).resolve(fileName);
        if (Files.notExists(file))
            return ResponseEntity.notFound().build();
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                .body(
                        Mono.just(new InputStreamResource(Files.newInputStream(file)))
                );
    }

}
