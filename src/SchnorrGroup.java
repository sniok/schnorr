import java.math.BigInteger;
import java.security.SecureRandom;

public class SchnorrGroup {
    public BigInteger p;
    public BigInteger q;
    public BigInteger g;

    SchnorrGroup(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    /**
     * Generates p, q, g from Schnorr group
     *
     * https://en.wikipedia.org/wiki/Schnorr_group
     *
     * @param bitLength
     */
    static SchnorrGroup generate(int bitLength) {

        BigInteger TWO = new BigInteger("2");

        SecureRandom sr = new SecureRandom();

        // Generate random q (prime)
        BigInteger q = new BigInteger(bitLength, 100, sr);


        // Generate p such as p = q*r + 1 (prime)
        BigInteger p;
        BigInteger r = BigInteger.ONE;
        while(true) {
            p = q.multiply(r).add(BigInteger.ONE);
            if(p.isProbablePrime(100)) break;

            r = r.add(BigInteger.ONE);
        }

        // Generate g – generator of subgroup
        // a ^ ga mod p != 1
        BigInteger g, a, ga;
        while(true) {
            a = (TWO.add(new BigInteger(bitLength, 100, sr))).mod(p);
            ga = (p.subtract(BigInteger.ONE)).divide(q);
            g = a.modPow(ga, p);
            if(g.compareTo(BigInteger.ONE) != 0) {
                break;
            }
        }

        return new SchnorrGroup(p,q,g);
    }
}
