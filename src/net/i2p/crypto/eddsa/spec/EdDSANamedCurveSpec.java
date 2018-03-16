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
package net.i2p.crypto.eddsa.spec;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.ScalarOps;

/**
 * EdDSA Curve specification that can also be referred to by name.
 * @author str4d
 *
 */
public final class EdDSANamedCurveSpec extends EdDSAParameterSpec {
    private final String name;

    public EdDSANamedCurveSpec(final String name, final Curve curve,
                               final String hashAlgo, final ScalarOps sc, final GroupElement B) {
        super(curve, hashAlgo, sc, B);
        this.name = name;
    }

    public final String getName() {
        return name;
    }
}
