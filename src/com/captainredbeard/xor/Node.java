package com.captainredbeard.xor;

/**
 * @author captain-redbeard
 * @version 1.00
 * @since 1/01/17
 */
public class Node {
    private String ipAddress;
    private PublicKey publicKey;

    public Node(String ipAddress, PublicKey publicKey) {
        this.ipAddress = ipAddress;
        this.publicKey = publicKey;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}
