package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyCredential;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.service.DecoyManagementService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Management API for decoy endpoints and credentials. All operations are audited.
 */
@RestController
@RequestMapping("/api/honeypot/decoys")
public class DecoyAdminController {

    private final DecoyManagementService managementService;

    public DecoyAdminController(DecoyManagementService managementService) {
        this.managementService = managementService;
    }

    @GetMapping("/endpoints")
    public List<DecoyEndpoint> listEndpoints() {
        return managementService.listEndpoints();
    }

    @PostMapping("/endpoints")
    public ResponseEntity<DecoyEndpoint> createEndpoint(
            @RequestBody DecoyEndpoint endpoint,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(managementService.createEndpoint(endpoint, operator));
    }

    @PostMapping("/endpoints/{id}/enable")
    public ResponseEntity<DecoyEndpoint> enableEndpoint(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return managementService.setEndpointStatus(id, true, operator)
                .map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/endpoints/{id}/disable")
    public ResponseEntity<DecoyEndpoint> disableEndpoint(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return managementService.setEndpointStatus(id, false, operator)
                .map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/endpoints/{id}")
    public ResponseEntity<Void> deleteEndpoint(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return managementService.deleteEndpoint(id, operator)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @GetMapping("/credentials")
    public List<DecoyCredential> listCredentials() {
        return managementService.listCredentials();
    }

    @PostMapping("/credentials")
    public ResponseEntity<DecoyCredential> createCredential(
            @RequestBody DecoyCredential credential,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(managementService.createCredential(credential, operator));
    }

    @PostMapping("/credentials/{id}/enable")
    public ResponseEntity<DecoyCredential> enableCredential(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return managementService.setCredentialStatus(id, true, operator)
                .map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/credentials/{id}/disable")
    public ResponseEntity<DecoyCredential> disableCredential(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return managementService.setCredentialStatus(id, false, operator)
                .map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/credentials/{id}")
    public ResponseEntity<Void> deleteCredential(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return managementService.deleteCredential(id, operator)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @ExceptionHandler(DecoyManagementService.DuplicateDecoyException.class)
    public ResponseEntity<Map<String, String>> handleDuplicate(DecoyManagementService.DuplicateDecoyException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", e.getMessage()));
    }

    @ExceptionHandler(DecoyManagementService.InvalidDecoyException.class)
    public ResponseEntity<Map<String, String>> handleInvalid(DecoyManagementService.InvalidDecoyException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
