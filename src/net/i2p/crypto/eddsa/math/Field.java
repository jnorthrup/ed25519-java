/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa.math;

/**
 * An EdDSA finite field. Includes several pre-computed values.
 * @author str4d
 *
 */
public final class Field   {
    private static final long serialVersionUID = 8746587465875676L;

    public final FieldElement ZERO;
    public final FieldElement ONE;
    public final FieldElement TWO;
    private final FieldElement FOUR;
    private final FieldElement FIVE;
    private final FieldElement EIGHT;

    private final int b;
    private final FieldElement q;
    /**
     * q-2
     */
    private final FieldElement qm2;
    /**
     * (q-5) / 8
     */
    private final FieldElement qm5d8;
    private final Encoding enc;

    public Field(final int b, final byte[] q, final Encoding enc) {
        this.b = b;
        this.enc = enc;
        this.enc.setField(this);

        this.q = fromByteArray(q);

        // Set up constants
        ZERO = fromByteArray(Constants.ZERO);
        ONE = fromByteArray(Constants.ONE);
        TWO = fromByteArray(Constants.TWO);
        FOUR = fromByteArray(Constants.FOUR);
        FIVE = fromByteArray(Constants.FIVE);
        EIGHT = fromByteArray(Constants.EIGHT);

        // Precompute values
        qm2 = this.getQ().subtract(TWO);
        qm5d8 = this.getQ().subtract(FIVE).divide(EIGHT);
    }

    public final FieldElement fromByteArray(final byte[] x) {
        return enc.decode(x);
    }

    public final int getb() {
        return getB();
    }

    public final FieldElement getQ() {
        return q;
    }

    public FieldElement getQm2() {
        return qm2;
    }

    public final FieldElement getQm5d8() {
        return qm5d8;
    }

    public final Encoding getEncoding(){
        return enc;
    }

    @Override
    public final int hashCode() {
        return getQ().hashCode();
    }

    @Override
    public final boolean equals(final Object obj) {
        if (!(obj instanceof Field))
            return false;
        final Field f = (Field) obj;
        return getB() == f.getB() && getQ().equals(f.getQ());
    }

    public int getB() {
        return b;
    }

}
