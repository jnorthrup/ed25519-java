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

import org.hamcrest.Matchers.*
import org.junit.Assert.*

import org.junit.Test

/**
 * @author str4d
 */
class EdDSANamedCurveTableTest {
    /**
     * Ensure curve names are case-inspecific
     */
    @Test
    fun curveNamesAreCaseInspecific() {
        val mixed = EdDSANamedCurveTable.getByName("Ed25519")
        val lower = EdDSANamedCurveTable.getByName("ed25519")
        val upper = EdDSANamedCurveTable.getByName("ED25519")

        assertThat(lower, `is`(equalTo(mixed)))
        assertThat(upper, `is`(equalTo(mixed)))
    }
}
