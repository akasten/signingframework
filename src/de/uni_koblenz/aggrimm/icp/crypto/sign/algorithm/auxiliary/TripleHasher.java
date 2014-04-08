package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary;

import java.math.BigInteger;
import java.security.MessageDigest;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.Triple;

/**
 * This class provides functions to calculate the hash for individual triples
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class TripleHasher {
	
	/**
	 * Hashs a triple using the approach of Melnik
	 * 
	 * @param t  triples to hash
	 * @param d  used digest method for hashing
	 * @return  hash value as byte array
	 * @throws Exception  if hashing fails
	 */
	public static BigInteger hashTripleMelnik(Triple t, MessageDigest d) throws Exception {	
		//Get digests of subject, predicate and object
		byte[] s = d.digest( t.getSubject().getBytes("UTF8") );
		byte[] p = d.digest( t.getPredicate().getBytes("UTF8") );
		byte[] o = d.digest( t.getObject().getBytes("UTF8") );
		
		//Prepare a new byte array which will contain all 3 digest
		int l = s.length;							//get the length
		byte[] b = new byte[l * 3];					//create a new array with a 3 times the length to have enough space for all 3 digests
		System.arraycopy(s, 0, b, 0, l);			//copy the subject into that array
		System.arraycopy(p, 0, b, l, l);			//copy the predicate into that array
		
		//Check if the object is a resource or a literal (objects starting with "<" are always a resource)
		if(t.getObject().startsWith("<")){
			//Just copy the object digest to array in case it is a resource
			System.arraycopy(o, 0, b, l*2, l);
		} else {
			//Rotate the object digest by one byte in case it is a literal and add it to the array
			for(int i=0; i < l; i++){
				b[l * 2 + ( (i+1) % l )] = o[i];
			}
		}
		
		return new BigInteger(d.digest(b));
	}

	
	/**
	 * Hashs a triple using simple string concatenation.
	 * 
	 * @param t  triples to hash
	 * @param d  used digest method for hashing
	 * @return  hash value as byte array
	 * @throws Exception  if hashing fails
	 * 
	 * @deprecated
	 */
	@Deprecated
	public static byte[] hashTripleConcatenation(Triple t, MessageDigest d) throws Exception {
		return d.digest(( t.getSubject() + " " + t.getPredicate() + " " + t.getObject() ).getBytes("UTF8"));
	}
	
}
