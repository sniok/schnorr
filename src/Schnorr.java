import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * Schnorr signature functions
 *
 * https://en.wikipedia.org/wiki/Schnorr_signature
 */
public class Schnorr {

    /**
     * Generates private and public keys x and y
     *
     * https://en.wikipedia.org/wiki/Schnorr_signature#Key_generation
     */
    static BigInteger[] generateKeys(SchnorrGroup group) {
        SecureRandom sr = new SecureRandom();

        // Private signing key. Random mod q
        BigInteger x = new BigInteger(16, sr).mod(group.q);

        // Public verification key
        BigInteger y = group.g.modPow(x, group.p);

        return new BigInteger[] { x, y };
    }

    /**
     * Generates signature { e, s } for message
     *
     * https://en.wikipedia.org/wiki/Schnorr_signature#Signing
     *
     * @param x - Private key
     */
    static BigInteger[] sign(SchnorrGroup group, byte[] message, BigInteger x) {

        SecureRandom sr = new SecureRandom();

        // Choose random k
        BigInteger k = new BigInteger(16, sr).mod(group.q);

        // r = g^k
        BigInteger r = group.g.modPow(k, group.p);

        // e = H( M || r )
        // Where H is a hash function (sha-1)
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        sha1.update(message);
        sha1.update(r.toByteArray());
        BigInteger e = new BigInteger(1, sha1.digest());

        // s = (k - xe) mod q
        BigInteger s = k.subtract(x.multiply(e)).mod(group.q);

        // The signature is the pair { e, s };
        return new BigInteger[] { e, s };
    }

    /**
     * Validates signature
     *
     * https://en.wikipedia.org/wiki/Schnorr_signature#Verifying
     *
     * @param y - Public verification key
     */
    static boolean isValid(SchnorrGroup group, BigInteger[] signature, byte[] message, BigInteger y) {
        BigInteger e = signature[0];
        BigInteger s = signature[1];

        // Calculate rv = g^s * y^e;
        BigInteger gs = group.g.modPow(s, group.p);
        BigInteger ye = y.modPow(e, group.p);
        BigInteger rv = gs.multiply(ye).mod(group.p);

        // Calculate hash
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
        sha1.update(message);
        sha1.update(rv.toByteArray());
        BigInteger ev = new BigInteger(1, sha1.digest());

        return ev.equals(e);
    }
}
