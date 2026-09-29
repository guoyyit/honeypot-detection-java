package com.github.guoyyit.honeypotdetectionjava.honeypot.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertNotifier;
import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.LoggingAlertNotifier;
import com.github.guoyyit.honeypotdetectionjava.honeypot.api.AdminAuthInterceptor;
import com.github.guoyyit.honeypotdetectionjava.honeypot.detection.DecoyCredentialDetector;
import com.github.guoyyit.honeypotdetectionjava.honeypot.detection.DecoyEndpointFilter;
import com.github.guoyyit.honeypotdetectionjava.honeypot.detection.SimulatedResponseRenderer;
import com.github.guoyyit.honeypotdetectionjava.honeypot.event.TouchEventProcessor;
import com.github.guoyyit.honeypotdetectionjava.honeypot.event.TouchEventService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.exemption.ExemptionService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.service.DecoyManagementService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AlertRepository;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AuditLog;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.DecoyRepository;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.ExemptionRuleRepository;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.TouchEventStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Path;

/**
 * Wires the honeypot subsystem beans.
 */
@Configuration
@EnableConfigurationProperties(HoneypotProperties.class)
public class HoneypotConfig implements WebMvcConfigurer {

    private final HoneypotProperties properties;

    public HoneypotConfig(HoneypotProperties properties) {
        this.properties = properties;
    }

    @Bean
    public DecoyRepository decoyRepository(HoneypotProperties properties, ObjectMapper mapper) {
        return new DecoyRepository(Path.of(properties.getDataDir()), mapper);
    }

    @Bean
    public TouchEventStore touchEventStore(HoneypotProperties properties, ObjectMapper mapper) {
        return new TouchEventStore(Path.of(properties.getDataDir()), mapper);
    }

    @Bean
    public AlertRepository alertRepository(HoneypotProperties properties, ObjectMapper mapper) {
        return new AlertRepository(Path.of(properties.getDataDir()), mapper);
    }

    @Bean
    public ExemptionRuleRepository exemptionRuleRepository(HoneypotProperties properties, ObjectMapper mapper) {
        return new ExemptionRuleRepository(Path.of(properties.getDataDir()), mapper);
    }

    @Bean
    public AuditLog auditLog(HoneypotProperties properties, ObjectMapper mapper) {
        return new AuditLog(Path.of(properties.getDataDir()), mapper);
    }

    @Bean
    public ExemptionService exemptionService(ExemptionRuleRepository repository) {
        return new ExemptionService(repository);
    }

    @Bean
    public AlertNotifier alertNotifier() {
        return new LoggingAlertNotifier();
    }

    @Bean
    public AlertService alertService(AlertRepository repository, AlertNotifier notifier,
                                     HoneypotProperties properties) {
        return new AlertService(repository, notifier, properties.getAlertCooldownMillis());
    }

    @Bean(destroyMethod = "stop")
    public TouchEventProcessor touchEventProcessor(TouchEventStore store, AlertService alertService) {
        TouchEventProcessor processor = new TouchEventProcessor(store, alertService);
        processor.start();
        return processor;
    }

    @Bean
    public TouchEventService touchEventService(TouchEventStore store, ExemptionService exemptionService,
                                               TouchEventProcessor processor) {
        return new TouchEventService(store, exemptionService, processor);
    }

    @Bean
    public SimulatedResponseRenderer simulatedResponseRenderer(ObjectMapper mapper) {
        return new SimulatedResponseRenderer(mapper);
    }

    @Bean
    public DecoyCredentialDetector decoyCredentialDetector(DecoyRepository repository,
                                                           TouchEventService touchEventService) {
        return new DecoyCredentialDetector(repository, touchEventService);
    }

    @Bean
    public DecoyManagementService decoyManagementService(DecoyRepository repository, AuditLog auditLog,
                                                         HoneypotProperties properties) {
        return new DecoyManagementService(repository, auditLog, properties.getAdminPathPrefix());
    }

    @Bean
    public FilterRegistrationBean<DecoyEndpointFilter> decoyEndpointFilter(
            DecoyRepository repository, TouchEventService touchEventService,
            SimulatedResponseRenderer renderer) {
        FilterRegistrationBean<DecoyEndpointFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new DecoyEndpointFilter(repository, touchEventService, renderer));
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registration;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AdminAuthInterceptor(properties))
                .addPathPatterns("/api/honeypot/**");
    }
}
