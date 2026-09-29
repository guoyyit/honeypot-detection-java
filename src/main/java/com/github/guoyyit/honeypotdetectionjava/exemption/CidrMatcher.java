package com.github.guoyyit.honeypotdetectionjava.exemption;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

final class CidrMatcher {

    private CidrMatcher() {
    }

    static boolean contains(String cidr, String ip) {
        if (cidr == null || ip == null) {
            return false;
        }
        try {
            String networkPart;
            int prefix;
            int slash = cidr.indexOf('/');
            if (slash >= 0) {
                networkPart = cidr.substring(0, slash);
                prefix = Integer.parseInt(cidr.substring(slash + 1));
            } else {
                networkPart = cidr;
                prefix = -1;
            }
            InetAddress network = parse(networkPart);
            InetAddress candidate = parse(ip);
            if (network.getClass() != candidate.getClass()) {
                return false;
            }
            if (prefix < 0) {
                return network.equals(candidate);
            }
            byte[] networkBytes = network.getAddress();
            byte[] candidateBytes = candidate.getAddress();
            int maxPrefix = networkBytes.length * 8;
            if (prefix < 0 || prefix > maxPrefix) {
                throw new IllegalArgumentException("Invalid prefix length: " + prefix);
            }
            BigInteger networkValue = new BigInteger(1, networkBytes);
            BigInteger candidateValue = new BigInteger(1, candidateBytes);
            if (prefix == 0) {
                return true;
            }
            BigInteger mask = BigInteger.ONE.shiftLeft(maxPrefix - prefix)
                    .subtract(BigInteger.ONE).not();
            return networkValue.and(mask).equals(candidateValue.and(mask));
        } catch (UnknownHostException | NumberFormatException e) {
            return false;
        }
    }

    static InetAddress parse(String value) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(value.trim());
        if (!(address instanceof Inet4Address) && !(address instanceof Inet6Address)) {
            throw new UnknownHostException("Unsupported address: " + value);
        }
        return address;
    }

    static boolean isValidCidr(String cidr) {
        try {
            String trimmed = cidr.trim();
            String networkPart = trimmed;
            int slash = trimmed.indexOf('/');
            if (slash >= 0) {
                networkPart = trimmed.substring(0, slash);
                int prefix = Integer.parseInt(trimmed.substring(slash + 1));
                int maxPrefix = parse(networkPart).getAddress().length * 8;
                return prefix >= 0 && prefix <= maxPrefix;
            }
            parse(networkPart);
            return true;
        } catch (UnknownHostException | NumberFormatException e) {
            return false;
        }
    }
}
