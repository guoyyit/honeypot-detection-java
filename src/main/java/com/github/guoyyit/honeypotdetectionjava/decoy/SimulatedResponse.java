package com.github.guoyyit.honeypotdetectionjava.decoy;

public class SimulatedResponse {
    private int statusCode = 200;
    private String contentType = "application/json";
    private String body = "";

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
