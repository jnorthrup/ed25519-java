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

import java.util.HashMap
import java.util.Locale
import java.util.Objects

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.BaseCurve
import net.i2p.crypto.eddsa.math.Curve
import net.i2p.crypto.eddsa.math.EdDSAFiniteField
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps

/**
 * The named EdDSA curves.
 * @author str4d
 */
object EdDSANamedCurveTable {
    val ED_25519 = "Ed25519"

    private val ED_25519_ED_DSA_FINITE_FIELD = EdDSAFiniteField(
            256, // b
            Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
            Ed25519LittleEndianEncoding().getEmptyEncoding())

    private val ed25519curve = BaseCurve(ED_25519_ED_DSA_FINITE_FIELD,
            Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
            ED_25519_ED_DSA_FINITE_FIELD.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))) // I

    //    public static final EdDSANamedCurveSpec ED_25519 = ; // Precompute tables for B

    @Volatile
    private var curves = HashMap<String, EdDSANamedCurveSpec>()

    @Synchronized
    private fun putCurve(name: String, curve: EdDSANamedCurveSpec) {
        val newCurves = HashMap(curves)
        newCurves[name] = curve
        curves = newCurves
    }

    private fun defineCurve(curve: EdDSANamedCurveSpec) {
        putCurve(curve.name.toLowerCase(Locale.ENGLISH), curve)
    }

    internal fun defineCurveAlias(name: String, alias: String) {
        val curve = curves[name.toLowerCase(Locale.ENGLISH)]!!
        Objects.requireNonNull<EdDSANamedCurveSpec>(curve)
        putCurve(alias.toLowerCase(Locale.ENGLISH), curve)
    }

    init {
        // RFC 8032
        defineCurve(EdDSANamedCurveSpec(
                ED_25519,
                ed25519curve,
                "SHA-512", // H
                Ed25519ScalarOps(), // l
                ed25519curve.createPoint( // B
                        Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
                        true)))
    }

    fun getByName(name: String): EdDSANamedCurveSpec {
        return curves[name.toLowerCase(Locale.ENGLISH)]!!
    }
}
