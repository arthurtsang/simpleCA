package com.youramaryllis.simpleca;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
@DependsOn("certCABuilder")
public class OcspResponder implements ApplicationListener<ContextRefreshedEvent> {
    @Autowired
    CertAuthDatabase database;
    @Autowired
    CertAuthority certAuthority;
    private ExecutorService executorService;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        executorService = Executors.newSingleThreadExecutor();
        executorService.submit(certAuthority.startOCSP(database.getAllCA()));
    }

    public void restart() {
        executorService.shutdownNow();
        executorService.submit(certAuthority.startOCSP(database.getAllCA()));
    }
}
