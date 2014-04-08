package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm;

import java.security.Key;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;

/**
 * This Interface specifies the methods which must be implemented by all signature algorithms.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public interface SignatureAlgorithmInterface {
	
	//######################################################## Graph Signing
	
	/**
	 * Canonicalizes a {@link GraphCollection} for a unique representation (commonly blank node removal/labeling and sorting).
	 * Must set {@link SignatureData#canonicalizationMethod} of {@link SignatureData}.
	 * 
	 * @param gc						graphCollection which is canonicalized
	 * @throws Exception
	 */
	public void canonicalize(GraphCollection gc) throws Exception;
	
	/**
	 * Executes extra steps after the actual canonicalization of a {@link GraphCollection}
	 * @param gc						graphCollection which is canonicalized
	 * @throws Exception
	 */
	public void postCanonicalize(GraphCollection gc) throws Exception;
	
	/**
	 * Calculates the hash value of a {@link GraphCollection} and safes it in its {@link SignatureData}.
	 * Must set {@link SignatureData#graphDigestMethod} and {@link SignatureData#serializationMethod} of {@link SignatureData}.
	 * 
	 * @param gc						graphCollection which is hashed
	 * @param digestAlgo				string specifying a digest algorithm
	 * @throws Exception
	 */
	public void hash(GraphCollection gc, String digestAlgo) throws Exception;

	/**
	 * Executes extra steps after the actual hash calculation of a {@link GraphCollection}
	 * @param gc						graphCollection which is hashed
	 * @throws Exception
	 */
	public void postHash(GraphCollection gc) throws Exception;	
	
	/**
	 * Signs {@link GraphCollection} (calculate signature(s) using a certificate/key and the hash value(s)).
	 * Must set {@link SignatureData#signatureMethod} of {@link SignatureData}.
	 * 
	 * @param gc						graphCollection which is signed
	 * @param privateKey				key used to calculate the signature
	 * @param verficiationCertificate	string specifying the certificate which should be used for verification
	 * @throws Exception
	 */
	public void sign(GraphCollection gc, Key privateKey, String verficiationCertificate) throws Exception;
	
	/**
	 * Assembles a {@link GraphCollection} (add signature(s) and a signature graph).
	 * 
	 * @param gc						graphCollection which is assembled
	 * @param signatureGraphName		string name for the signature graph
	 * @throws Exception
	 */
	public void assemble(GraphCollection gc, String signatureGraphName) throws Exception ;
	
	
	//######################################################## Graph Verification
	
	/**
	 * Verifies a signed graph collection using a public key
	 * Involves canonicalization and hashing of the graph collection and a cryptographic signature check
	 * 
	 * @param gc						graphCollection which will be verified
	 * @param publicKey					key for the cryptographic signature check
	 * @return							boolean true if verification succeeded, false otherwise
	 * @throws Exception
	 */
	public boolean verify(GraphCollection gc, Key publicKey) throws Exception;
	
	
	//######################################################## Helper Function
	
	/**
	 * Gets the name of the signature algorithm (used for identification of the algorithm when signing/verifying)
	 * 
	 * @return							string name of the algorithm
	 */
	public String getName();
	
}
