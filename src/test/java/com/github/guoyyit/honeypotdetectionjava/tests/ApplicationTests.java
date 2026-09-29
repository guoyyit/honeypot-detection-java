package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Vincent
 * @version 1.0
 */
@SpringBootTest
public class ApplicationTests {

    private static final Path DATA_DIR = createTempDir();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.data-dir", DATA_DIR::toString);
    }

    @Test
    public void contentLoad() {
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("honeypot-app-tests-");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
