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

interface ScalarOps {
    /**
     * Reduce the given scalar mod $l$.
     *
     *
     * From the Ed25519 paper:<br></br>
     * Here we interpret $2b$-bit strings in little-endian form as integers in
     * $\{0, 1,..., 2^{(2b)}-1\}$.
     * @param s the scalar to reduce
     * @return $s \bmod l$
     */
    fun reduce(s: ByteArray): ByteArray

    /**
     * $r = (a * b + c) \bmod l$
     * @param a a scalar
     * @param b a scalar
     * @param c a scalar
     * @return $(a*b + c) \bmod l$
     */
    fun multiplyAndAdd(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray
}
