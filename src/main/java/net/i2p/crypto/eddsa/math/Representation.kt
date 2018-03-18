package net.i2p.crypto.eddsa.math

/**
 * Available representations for a group element.
 *
 *  * P2: Projective representation $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$.
 *  * P3: Extended projective representation $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$.
 *  * P3PrecomputedDouble: P3 but with dblPrecmp populated.
 *  * P1P1: Completed representation $((X:Z), (Y:T))$ satisfying $x=X/Z, y=Y/T$.
 *  * PRECOMP: Precomputed representation $(y+x, y-x, 2dxy)$.
 *  * CACHED: Cached representation $(Y+X, Y-X, Z, 2dT)$
 *
 */
enum class Representation {
    /**
     * Projective ($P^2$): $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$
     */
    P2 {
        override fun toRep(groupElement: GroupElement): GroupElement {
            when (groupElement.repr) {
                P2 -> return P2GroupElement(groupElement.curve, groupElement.x, groupElement.y, groupElement.z)
                P3 -> return P2GroupElement(groupElement.curve, groupElement.x, groupElement.y, groupElement.z)
                P1P1 -> return P2GroupElement(groupElement.curve, groupElement.x.multiply(groupElement.t), groupElement.y.multiply(groupElement.z), groupElement.z.multiply(groupElement.t))
                PRECOMP -> throw IllegalArgumentException()
                CACHED -> throw IllegalArgumentException()
                else -> throw UnsupportedOperationException()
            }
        }
    },
    /**
     * Extended ($P^3$): $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$
     */
    P3 {
        override fun toRep(groupElement: GroupElement): GroupElement {
            when (groupElement.repr) {
                P2 -> throw IllegalArgumentException()
                P3 -> {
                    val curve1 = groupElement.curve
                    val x = groupElement.x
                    val y = groupElement.y
                    val z = groupElement.z
                    val t = groupElement.t
                    /**
                     * Creates a new group element in P3 representation.
                     *
                     * @param curve The curve.
                     * @param X The $X$ coordinate.
                     * @param Y The $Y$ coordinate.
                     * @param Z The $Z$ coordinate.
                     * @param T The $T$ coordinate.
                     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
                     * @return The group element in P3 representation.
                     */
                    return if (false) P3PreGroupElement(curve1, x, y, z, t) else P3GroupElement(curve1, x, y, z, t)
                }
                P1P1 -> {

                    val curve2 = groupElement.curve
                    val x1 = groupElement.x.multiply(groupElement.t)
                    val y1 = groupElement.y.multiply(groupElement.z)
                    val z1 = groupElement.z.multiply(groupElement.t)
                    val t1 = groupElement.x.multiply(groupElement.y)
                    /**
                     * Creates a new group element in P3 representation.
                     *
                     * @param curve The curve.
                     * @param X The $X$ coordinate.
                     * @param Y The $Y$ coordinate.
                     * @param Z The $Z$ coordinate.
                     * @param T The $T$ coordinate.
                     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
                     * @return The group element in P3 representation.
                     */
                    return P3GroupElement(curve2, x1, y1, z1, t1)
                }
                PRECOMP -> throw IllegalArgumentException()
                CACHED -> throw IllegalArgumentException()
                else -> throw UnsupportedOperationException()
            }
        }
    },
    /**
     * P3 but also populate dblPrecmp
     */
    P3PrecomputedDouble {
        override fun toRep(groupElement: GroupElement): GroupElement {
            when (groupElement.repr) {
                P2 -> throw IllegalArgumentException()
                P3 -> throw IllegalArgumentException()
                P1P1 -> {
                    val curve1 = groupElement.curve
                    val x = groupElement.x.multiply(groupElement.t)
                    val y = groupElement.y.multiply(groupElement.z)
                    val z = groupElement.z.multiply(groupElement.t)
                    val t = groupElement.x.multiply(groupElement.y)
                    /**
                     * Creates a new group element in P3 representation.
                     *
                     * @param curve The curve.
                     * @param X The $X$ coordinate.
                     * @param Y The $Y$ coordinate.
                     * @param Z The $Z$ coordinate.
                     * @param T The $T$ coordinate.
                     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
                     * @return The group element in P3 representation.
                     */
                    return P3PreGroupElement(curve1, x, y, z, t)
                }
                PRECOMP -> throw IllegalArgumentException()
                CACHED -> throw IllegalArgumentException()
                else -> throw UnsupportedOperationException()
            }
        }
    },
    /**
     * Completed ($P \times P$): $((X:Z),(Y:T))$ satisfying $x=X/Z, y=Y/T$
     */
    P1P1 {
        override fun toRep(groupElement: GroupElement): GroupElement {
            if (groupElement.repr === Representation.P1P1) {

                /**
                 * Creates a new group element in P1P1 representation.
                 *
                 * @param curve The curve.
                 * @param X The $X$ coordinate.
                 * @param Y The $Y$ coordinate.
                 * @param Z The $Z$ coordinate.
                 * @param T The $T$ coordinate.
                 * @return The group element in P1P1 representation.
                 */
                return P1pGroupElement(groupElement.curve, groupElement.x, groupElement.y, groupElement.z, groupElement.t)
            }
            if (groupElement.repr === Representation.P2 || groupElement.repr === Representation.P3 || groupElement.repr === Representation.PRECOMP || groupElement.repr === Representation.CACHED)
                throw IllegalArgumentException()
            throw UnsupportedOperationException()
        }
    },
    /**
     * Precomputed (Duif): $(y+x,y-x,2dxy)$
     */
    PRECOMP {
        override fun toRep(groupElement: GroupElement): GroupElement {
            if (groupElement.repr === Representation.PRECOMP) {
                return PrecompGroupElement(groupElement.curve, groupElement.x, groupElement.y, groupElement.z)


            }
            if (groupElement.repr === Representation.P2 || groupElement.repr === Representation.P3 || groupElement.repr === Representation.P1P1 || groupElement.repr === Representation.CACHED)
                throw IllegalArgumentException()
            throw UnsupportedOperationException()
        }
    },
    /**
     * Cached: $(Y+X,Y-X,Z,2dT)$
     */
    CACHED {
        override fun toRep(groupElement: GroupElement): GroupElement {
            when (groupElement.repr) {
                P3 -> return CachedGroupElement(groupElement.curve, groupElement.y.add(groupElement.x), groupElement.y.subtract(groupElement.x), groupElement.z, groupElement.t.multiply(groupElement.curve.d2))
                P1P1, PRECOMP, P2 -> throw IllegalArgumentException()
                CACHED -> return CachedGroupElement(groupElement.curve, groupElement.x, groupElement.y, groupElement.z, groupElement.t)
                else -> throw UnsupportedOperationException()
            }
        }
    };

    /**
     * Convert a GroupElement from one Representation to another.
     * TODO-CR: Add additional conversion?
     * $r = p$
     *
     *
     * Supported conversions:
     *
     *
     *  * P3 $\rightarrow$ P2
     *  * P3 $\rightarrow$ CACHED (1 multiply, 1 add, 1 subtract)
     *  * P1P1 $\rightarrow$ P2 (3 multiply)
     *  * P1P1 $\rightarrow$ P3 (4 multiply)
     *
     * @param groupElement@return A new group element in the given representation.
     */
    abstract fun toRep(groupElement: GroupElement): GroupElement
}
