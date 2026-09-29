package com.github.guoyyit.honeypotdetectionjava.decoy;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DecoyResource {
    private String id;
    private String name;
    private DecoyType type;
    private DecoyStatus status = DecoyStatus.ENABLED;
    private int sensitivity;
    private String path;
    private SimulatedResponse simulatedResponse;
    private String decoyUsername;
    private String decoyPasswordHash;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String decoyPassword;
    private long createdAt;
    private long updatedAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public DecoyType getType() {
        return type;
    }

    public void setType(DecoyType type) {
        this.type = type;
    }

    public DecoyStatus getStatus() {
        return status;
    }

    public void setStatus(DecoyStatus status) {
        this.status = status;
    }

    public int getSensitivity() {
        return sensitivity;
    }

    public void setSensitivity(int sensitivity) {
        this.sensitivity = sensitivity;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public SimulatedResponse getSimulatedResponse() {
        return simulatedResponse;
    }

    public void setSimulatedResponse(SimulatedResponse simulatedResponse) {
        this.simulatedResponse = simulatedResponse;
    }

    public String getDecoyUsername() {
        return decoyUsername;
    }

    public void setDecoyUsername(String decoyUsername) {
        this.decoyUsername = decoyUsername;
    }

    public String getDecoyPasswordHash() {
        return decoyPasswordHash;
    }

    public void setDecoyPasswordHash(String decoyPasswordHash) {
        this.decoyPasswordHash = decoyPasswordHash;
    }

    public String getDecoyPassword() {
        return decoyPassword;
    }

    public void setDecoyPassword(String decoyPassword) {
        this.decoyPassword = decoyPassword;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }
}
