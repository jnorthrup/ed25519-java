/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https:></https:>//creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa.spec

import net.i2p.crypto.eddsa.math.BaseGroupElement
import net.i2p.crypto.eddsa.math.Curve
import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.math.ScalarOps

/**
 * EdDSA Curve specification that can also be referred to by name.
 * @author str4d
 */
class EdDSANamedCurveSpec(val name: String, curve: Curve,
                          hashAlgo: String, sc: ScalarOps, B: GroupElement) : EdDSAParameterSpec(curve, hashAlgo, sc, B)
