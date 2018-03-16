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
package net.i2p.crypto.eddsa

import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec

/**
 * Common interface for all EdDSA keys.
 * @author str4d
 */
@FunctionalInterface
internal interface EdDSAKey {

    /**
     * @return a parameter specification representing the EdDSA domain
     * parameters for the key.
     */
    val params: EdDSAParameterSpec

    companion object {
        /**
         * The reported key algorithm for all EdDSA keys
         */
        val KEY_ALGORITHM = "EdDSA"
    }
}
