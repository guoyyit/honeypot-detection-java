package com.github.guoyyit.honeypotdetectionjava.web;

import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AdminController.AdminUnauthorizedException.class)
    public ResponseEntity<Map<String, String>> handleUnauthorized(
            AdminController.AdminUnauthorizedException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "unauthorized"));
    }

    @ExceptionHandler(DecoyService.DuplicateDecoyException.class)
    public ResponseEntity<Map<String, String>> handleConflict(
            DecoyService.DuplicateDecoyException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException e) {
        HttpStatus status = e.getMessage() != null
                && (e.getMessage().contains("not found"))
                ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
    }
}
