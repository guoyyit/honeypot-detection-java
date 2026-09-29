package com.github.guoyyit.honeypotdetectionjava.tests;

import java.net.ServerSocket;

final class SocketPorts {

    private SocketPorts() {
    }

    static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (Exception e) {
            throw new IllegalStateException("no free port", e);
        }
    }
}
