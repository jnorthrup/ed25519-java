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
package net.i2p.crypto.eddsa.math

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

internal object PrecomputationTestVectors {
    // Test files were generated using base.py and base2.py from ref10
    // (by printing hex(x%q) instead of the radix-255 representation).
    val testPrecmp = getPrecomputation("basePrecmp")
    val testDblPrecmp = getDoublePrecomputation("baseDblPrecmp")

    private fun getPrecomputation(fileName: String): Array<Array<GroupElement>> {
        val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        val curve = ed25519.curve
        val edDSAFiniteField = curve.edDSAFiniteField
        val precmp = Array<Array<GroupElement?>>(32) { arrayOfNulls(8) }
        var file: BufferedReader? = null
        var row = 0
        var col = 0
        try {
            val `is` = PrecomputationTestVectors::class.java.getResourceAsStream(fileName)
                    ?: throw IOException("Resource not found: $fileName")
            file = BufferedReader(InputStreamReader(`is`))
            while (true) {
                val line = file.readLine()
                if (null != line) {
                    if (" }," != line) {
                        if ("}," != line) {
                            if (line.startsWith("  { ")) {
                                val ypxStr = line.substring(4, line.lastIndexOf(' '))
                                val ypx = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(ypxStr))
                                val s = file.readLine()
                                val ymxStr = s.substring(4, s.lastIndexOf(' '))
                                val ymx = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(ymxStr))
                                val s3 = file.readLine()
                                val xy2dStr = s3.substring(4, s3.lastIndexOf(' '))
                                val xy2d = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(xy2dStr))
                                precmp[row][col] = PrecompGroupElement(curve, ypx, ymx, xy2d)
                            }
                        } else {
                            col = 0
                            row += 1
                        }
                    } else {
                        col += 1
                    }
                } else {
                    break
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            if (null != file) try {
                file.close()
            } catch (e: IOException) {
            }

        }
        return precmp as Array<Array<GroupElement>>
    }

    private fun getDoublePrecomputation(fileName: String): Array<GroupElement> {
        val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        val curve = ed25519.curve
        val edDSAFiniteField = curve.edDSAFiniteField
        val dblPrecmp = arrayOfNulls<GroupElement>(8)
        var file: BufferedReader? = null
        var row = 0
        try {
            val `is` = PrecomputationTestVectors::class.java.getResourceAsStream(fileName)
                    ?: throw IOException("Resource not found: $fileName")
            file = BufferedReader(InputStreamReader(`is`))
            while (true) {
                val line = file.readLine()
                if (null != line) {
                    if (" }," != line) {
                        if (line.startsWith("  { ")) {
                            val ypxStr = line.substring(4, line.lastIndexOf(' '))
                            val ypx = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(ypxStr))
                            val s2 = file.readLine()
                            val ymxStr = s2.substring(4, s2.lastIndexOf(' '))
                            val ymx = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(ymxStr))
                            val s4 = file.readLine()
                            val xy2dStr = s4.substring(4, s4.lastIndexOf(' '))
                            val xy2d = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(xy2dStr))
                            dblPrecmp[row] = PrecompGroupElement(curve, ypx, ymx, xy2d)
                        }
                    } else {
                        row += 1
                    }
                } else {
                    break
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            if (null != file) try {
                file.close()
            } catch (e: IOException) {
            }

        }
        return dblPrecmp as Array<GroupElement>
    }
}
