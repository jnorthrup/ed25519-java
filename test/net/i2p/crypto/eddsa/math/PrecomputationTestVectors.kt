/**
 * EdDSA-Java by str4d
 *
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https:></https:>//creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa.math

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader

interface PrecomputationTestVectors {
    companion object {
        // Test files were generated using base.py and base2.py from ref10
        // (by printing hex(x%q) instead of the radix-255 representation).
        val testPrecmp = getPrecomputation("basePrecmp")
        val testDblPrecmp = getDoublePrecomputation("baseDblPrecmp")

        fun getPrecomputation(fileName: String): Array<Array<GroupElement>> {
            val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
            val curve = ed25519.curve
            val finiteField = curve.field
            val precmp = Array<Array<GroupElement>>(32) { arrayOfNulls(8) }
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
                        if (" }," == line)
                            col += 1
                        else if ("}," == line) {
                            col = 0
                            row += 1
                        } else if (line.startsWith("  { ")) {
                            val ypxStr = line.substring(4, line.lastIndexOf(' '))
                            val ypx = finiteField.fromByteArray(
                                    Utils.hexToBytes(ypxStr))
                            val line2 = file.readLine()
                            val ymxStr = line2.substring(4, line2.lastIndexOf(' '))
                            val ymx = finiteField.fromByteArray(
                                    Utils.hexToBytes(ymxStr))
                            run {
                                val line1 = file.readLine()
                                val xy2dStr = line1.substring(4, line1.lastIndexOf(' '))
                                val xy2d = finiteField.fromByteArray(
                                        Utils.hexToBytes(xy2dStr))
                                precmp[row][col] = GroupElement.precomp(curve,
                                        ypx, ymx, xy2d)
                            }
                        }
                    } else {
                        break
                    }
                }
            } catch (e: IOException) {
                e.printStackTrace()
            } finally {
                if (null != file)
                    try {
                        file.close()
                    } catch (e: IOException) {
                    }

            }
            return precmp
        }

        fun getDoublePrecomputation(fileName: String): Array<GroupElement> {
            val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
            val curve = ed25519.curve
            val finiteField = curve.field
            val dblPrecmp = arrayOfNulls<GroupElement>(8)
            var file: BufferedReader? = null
            var row = 0
            try {
                val `is` = PrecomputationTestVectors::class.java.getResourceAsStream(fileName)
                        ?: throw IOException("Resource not found: $fileName")
                file = BufferedReader(InputStreamReader(`is`))
                var line: String?
                do {
                    line = file.readLine()
                    if (null != line) {
                        if (" }," == line) {
                            row += 1
                        } else if (line.startsWith("  { ")) {
                            val ypxStr = line.substring(4, line.lastIndexOf(' '))
                            val ypx = finiteField.fromByteArray(
                                    Utils.hexToBytes(ypxStr))
                            line = file.readLine()
                            val ymxStr = line!!.substring(4, line.lastIndexOf(' '))
                            val ymx = finiteField.fromByteArray(
                                    Utils.hexToBytes(ymxStr))
                            line = file.readLine()
                            val xy2dStr = line!!.substring(4, line.lastIndexOf(' '))
                            val xy2d = finiteField.fromByteArray(
                                    Utils.hexToBytes(xy2dStr))
                            dblPrecmp[row] = GroupElement.precomp(curve,
                                    ypx, ymx, xy2d)
                        }
                    } else {
                        break
                    }
                } while (true)
            } catch (e: IOException) {
                e.printStackTrace()
            } finally {
                if (null != file)
                    try {
                        file.close()
                    } catch (e: IOException) {
                    }

            }
            return dblPrecmp
        }
    }
}
