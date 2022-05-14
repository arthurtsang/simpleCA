package com.youramaryllis.simpleca;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import groovy.text.SimpleTemplateEngine;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SimpleCertAuthApplication {
    private static ApplicationContext applicationContext;

    public static void main(String[] args) {
        applicationContext = SpringApplication.run(SimpleCertAuthApplication.class, args);
        ObjectMapper objectMapper = applicationContext.getBean(ObjectMapper.class);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    }

    @Bean
    public SimpleTemplateEngine simpleTemplateEngine() {
        return new SimpleTemplateEngine();
    }
}
