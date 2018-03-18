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
package net.i2p.crypto.eddsa.math.ed25519

import net.i2p.crypto.eddsa.math.*

/**
 * Helper class for encoding/decoding from/to the 32 byte representation.
 *
 *
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
class Ed25519LittleEndianEncoding {

    val emptyEncoding = MyEmptyEncoding(this)

    var edDSAFiniteField: EdDSAFiniteField?
        get() = emptyEncoding.edDSAFiniteField
        set(f) {
            emptyEncoding.edDSAFiniteField = f
        }

    fun getEmptyEncoding(): EmptyEncoding {
        return emptyEncoding
    }

    companion object {

        internal fun load_3(`in`: ByteArray, offset: Int): Int {
            var offset1 = offset
            var result = `in`[offset1++]   as Int  and 0xff
            result = result or (`in`[offset1++] as Int  and 0xff shl 8)
            result = result or (`in`[offset1]   as Int  and 0xff shl 16)
            return result
        }

        internal fun load_4(`in`: ByteArray, offset: Int): Long {
            var offset1 = offset
            var result = `in`[offset1++]as Int  and 0xff
            result = result or (`in`[offset1++]as Int  and 0xff shl 8)
            result = result or (`in`[offset1++]as Int  and 0xff shl 16)
            result = result.or(`in`[offset1]as Int  shl 24)
            return result.toLong() and 0xffffffffL
        }
    }

}
