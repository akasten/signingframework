package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary;

import java.math.BigInteger;
import java.util.Random;

/**
 * Combine hashes
 * There are 3 possible combination algorithms:
 * 
 * 	  Method									Speed		Security
 * ---------------------------------------------------------------------
 * 	- Xor										fast		low
 *  - Addition modulo N							average		average
 *  - Multiplication modulo N					slow		high
 *  
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class HashCombinator {
	
	/**
	 * Modulo Number
	 * 
	 * 64-bit prime: 2^64 - 59 = 18446744073709551557
	 *     BigInteger("2").pow(64).subtract(new BigInteger("59"));
	 * 3072-bit prime: 2^3072 - 1103717
	 *     BigInteger("2").pow(3072).subtract(new BigInteger("1103717"));
	 * 2048-bit prime: 2^2048 - 11837
	 *     BigInteger("2").pow(2048).subtract(new BigInteger("11837"));
	 */
	public static final BigInteger N_MUL = BigInteger.probablePrime(1024, new Random(Long.MAX_VALUE));
	public static final BigInteger N_XOR = BigInteger.probablePrime(256,  new Random(Long.MAX_VALUE));
	public static final BigInteger N_ADD = BigInteger.probablePrime(1024, new Random(Long.MAX_VALUE));
	
	//Combination algorithms
	public enum ca {
	    Xor, Add, Multiply
	}
	
	//######################################################## Combination Functions
	
	/**
	 * Combines two byte[] hashes
	 * 
	 * @param hashA  first hash value to combine
	 * @param hashB  second hash value to combine
	 * @param algorithm  used combination algorithm ({@link ca})
	 * @return  combined hash value as byte array
	 */
	static public byte[] combine(byte[] hashA, byte[] hashB, ca algorithm){
		BigInteger a=new BigInteger(hashA);
		BigInteger b=new BigInteger(hashB);
		switch (algorithm) {
			//Exclusive or (XOR)
			case Xor:
				return a.xor(b).toByteArray(); 
			//Addition modulo N
			case Add:
				return a.add(b).mod(N_ADD).toByteArray();
			//Multiplication modulo N
			case Multiply:
			default:
				return a.multiply(b).mod(N_MUL).toByteArray();
		}
	}
	
	/**
	 * Combines two BigInteger hashes (requires no conversion from/to byte[])
	 * 
	 * @param a  first hash value to combine
	 * @param b  second hash value to combine
	 * @param algorithm  used combination algorithm ({@link ca})
	 * @return  combined hash value as BigInteger
	 */
	static public BigInteger combine(BigInteger a, BigInteger b, ca algorithm){
		switch (algorithm) {
			//Exclusive or (XOR)
			case Xor:
				return a.xor(b); 
			//Addition modulo N
			case Add:
				return a.add(b).mod(N_ADD);
			//Multiplication modulo N
			case Multiply:
			default:
				return a.multiply(b).mod(N_MUL);
		}
	}
}
