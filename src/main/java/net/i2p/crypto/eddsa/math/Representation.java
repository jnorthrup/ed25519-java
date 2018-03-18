package net.i2p.crypto.eddsa.math;

/**
 * Available representations for a group element.
 * <ul>
 * <li>P2: Projective representation $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$.
 * <li>P3: Extended projective representation $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$.
 * <li>P3PrecomputedDouble: P3 but with dblPrecmp populated.
 * <li>P1P1: Completed representation $((X:Z), (Y:T))$ satisfying $x=X/Z, y=Y/T$.
 * <li>PRECOMP: Precomputed representation $(y+x, y-x, 2dxy)$.
 * <li>CACHED: Cached representation $(Y+X, Y-X, Z, 2dT)$
 * </ul>
 */
public enum Representation {
    /**
     * Projective ($P^2$): $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$
     */
    P2,
    /**
     * Extended ($P^3$): $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$
     */
    P3,
    /**
     * P3 but also populate dblPrecmp
     */
    P3PrecomputedDouble,
    /**
     * Completed ($P \times P$): $((X:Z),(Y:T))$ satisfying $x=X/Z, y=Y/T$
     */
    P1P1,
    /**
     * Precomputed (Duif): $(y+x,y-x,2dxy)$
     */
    PRECOMP,
    /**
     * Cached: $(Y+X,Y-X,Z,2dT)$
     */
    CACHED
}
