package com.captainredbeard.xor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @author captain-redbeard
 * @version 1.00
 * @since 1/01/17
 */
public class Onion {
    private final int maxLen = 256;
    private Node[] nodes;
    private byte[] chunkSeparator;
    private byte[] itemSeparator;
    private byte[] splitSeparator;

    /**
     * Construct an Onion.
     *
     * @param nodes
     */
    public Onion(Node[] nodes) {
        this.nodes = nodes;
        this.chunkSeparator = new byte[]{0x7e};
        this.itemSeparator = new byte[]{0x3a};
        this.splitSeparator = new byte[]{0x2c};
    }

    /**
     * Encrypt message in layers by each public key.
     *
     * @param message - data to be encrypted
     * @return BigInteger
     */
    public BigInteger create(BigInteger message) {
        ByteArrayOutputStream outputStream;
        byte[] onion = message.toByteArray();
        byte[][] chunks;

        for (int i = 0; i < nodes.length; i++) {
            outputStream = new ByteArrayOutputStream();
            chunks = splitBytes(onion, maxLen);

            for (byte[] c : chunks) {
                try {
                    BigInteger enc = nodes[i].getPublicKey().encodeRaw(new BigInteger(c));
                    outputStream.write(Base64.encode(enc.toByteArray()));
                    outputStream.write(chunkSeparator);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            try {
                onion = outputStream.toByteArray();

                if (i != 0) {
                    String layer = "destination:" + nodes[i].getIpAddress() + ",data:" + new String(onion);
                    onion = layer.getBytes();
                }

                outputStream.flush();
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        //Return onion
        return new BigInteger(onion);
    }

    /**
     * Peel a layer by the private key.
     *
     * @param data
     * @param key
     * @return BigInteger
     */
    public BigInteger peel(BigInteger data, PrivateKey key) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        List<byte[]> split = splitByteArray(data.toByteArray(), splitSeparator);
        List<byte[]> chunks;
        byte[] layer = null;

        if (split.size() > 1) {
            chunks = splitByteArray(splitByteArray(split.get(1), itemSeparator).get(1), chunkSeparator);
        } else {
            chunks = splitByteArray(data.toByteArray(), chunkSeparator);
        }

        for (byte[] c : chunks) {
            if (c.length > 0) {
                try {
                    BigInteger dec = key.decodeCRT(new BigInteger(Base64.decode(c)));
                    outputStream.write(dec.toByteArray());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        try {
            layer = outputStream.toByteArray();
            outputStream.flush();
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Return onion
        return new BigInteger(layer);
    }

    /**
     * Split byte array by size.
     *
     * @param data - data to be split
     * @param chunkSize - size of each byte[] to be returned
     * @return byte[][]
     */
    private static byte[][] splitBytes(byte[] data, int chunkSize) {
        int length = data.length;
        byte[][] byteArrays = new byte[(length + chunkSize - 1)/chunkSize][];
        int destIndex = 0;
        int stopIndex = 0;

        for (int startIndex = 0; startIndex + chunkSize <= length; startIndex += chunkSize) {
            stopIndex += chunkSize;
            byteArrays[destIndex++] = Arrays.copyOfRange(data, startIndex, stopIndex);
        }

        if (stopIndex < length) {
            byteArrays[destIndex] = Arrays.copyOfRange(data, stopIndex, length);
        }

        //Return byte arrays
        return byteArrays;
    }

    /**
     * Split byte array by delimiter.
     *
     * @param array
     * @param delimiter
     * @return List<byte[]>
     */
    private List<byte[]> splitByteArray(byte[] array, byte[] delimiter) {
        List<byte[]> byteArrays = new LinkedList<>();
        int begin = 0;

        if (delimiter.length == 0) {
            return byteArrays;
        }

        outer:
        for (int i = 0; i < array.length - delimiter.length + 1; i++) {
            for (int j = 0; j < delimiter.length; j++) {
                if (array[i + j] != delimiter[j]) {
                    continue outer;
                }
            }

            byteArrays.add(Arrays.copyOfRange(array, begin, i));
            begin = i + delimiter.length;
        }

        byteArrays.add(Arrays.copyOfRange(array, begin, array.length));

        //Return arrays
        return byteArrays;
    }

}
