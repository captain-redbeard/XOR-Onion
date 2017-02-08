package tests;

import com.captainredbeard.xor.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;

/**
 * @author captain-redbeard
 * @version 1.00
 * @since 1/01/17
 */
public class TestOnion {
    private static int success;
    private static int failed;

    public static void main(String[] args) throws IOException {
        int tests = 1;
        int subTests = 10;
        int nodes = 5;

        for (int i = 0; i < tests; i++) {
            test(nodes, subTests);
        }

        System.out.println();
        System.out.println("-- Test Results --");
        System.out.println("Tests ran: \t\t" + tests * subTests);
        System.out.println("Failed: \t\t" + failed);
        System.out.println("Success: \t\t" + success);
        System.out.println("Overall pass: \t" + (success == (tests * subTests)));
    }

    public static void test(int nodeCount, int subTests) throws IOException {
        final RSA rsa = new RSA();
        Keypair[] keypairs = new Keypair[nodeCount];
        Node[] nodes = new Node[nodeCount];

        //Generate key pairs
        System.out.println("Generating " + nodeCount + " keys pairs.");

        for (int i = 0; i < nodeCount; i++) {
            try {
                //Create key pair
                keypairs[i] = rsa.generateKeypair(rsa.MIN_KEY_LENGTH);

                //Echo results
                System.out.println(" - " + keypairs[i]);

                //Create node
                nodes[i] = new Node("127.0.0.1", keypairs[i].getPublicKey());
            } catch(InvalidKeyException e) {
                e.printStackTrace();
            }
        }

        //Create onion
        long start, end;

        for (int j = 0; j < subTests; j++) {
            System.out.println("Creating onion.");
            String message = "Hello World! " +
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ " +
                    "abcdefghijklmnopqrstuvwxyz " +
                    "0123456789 " +
                    "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";
            BigInteger paddedMessage = new BigInteger(rsa.addPadding(message.getBytes(), 256));
            Onion onion = new Onion(nodes);
            start = System.currentTimeMillis();
            BigInteger data = onion.create(paddedMessage);
            end = System.currentTimeMillis() - start;

            //Echo results
            System.out.println(" - raw data: \t" + message);
            System.out.println(" - data bi: \t" + new BigInteger(message.getBytes()));
            System.out.println(" - created in: \t" + end + "ms");
            System.out.println(" - length: \t\t" + data.bitLength() + "bits");
            System.out.println(" - layers: \t\t" + nodes.length);

            //Peel layers
            System.out.println("Peeling layers.");
            for (int i = nodes.length - 1; i > -1; i--) {
                System.out.println(" - layer: \t" + (i + 1));

                start = System.currentTimeMillis();
                data = onion.peel(data, keypairs[i].getPrivateKey());
                end = System.currentTimeMillis() - start;

                System.out.println(" \t- peeled in: \t" + end + "ms");
                System.out.println(" \t- data length: \t" + data.bitLength() + "bits");
            }

            //Remove padding
            data = new BigInteger(rsa.removePadding(data.toByteArray(), 256));

            System.out.println();
            System.out.println("Decrypted data: " + new String(data.toByteArray()));
            System.out.println();
            System.out.println("----------------------");
            System.out.println();

            if (message.equals(new String(data.toByteArray()))) {
                success++;
            } else {
                failed++;
            }
        }
    }

}
