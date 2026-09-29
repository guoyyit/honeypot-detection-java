package com.github.guoyyit.honeypotdetectionjava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableConfigurationProperties(HoneypotProperties.class)
@EnableAsync
@EnableScheduling
public class ApplicationConfig {
}
