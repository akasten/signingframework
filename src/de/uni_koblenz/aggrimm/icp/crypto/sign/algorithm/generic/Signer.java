package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic;

import java.security.Key;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.GraphCollection;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.SignatureData;

/**
 * Standard {@link GraphCollection} signer
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class Signer {
	
	/**
	 * Signs a {@link GraphCollection}
	 * 
	 * @param gc						{@link GraphCollection} to sign
	 * @param privateKey				private key for signature calculation
	 * @param verficiationCertificate	certificate information
	 * @throws Exception
	 */
	public static void sign(GraphCollection gc, Key privateKey, String verficiationCertificate) throws Exception {
		//Signature Data existing?
		if (!gc.hasSignature()){
			throw new Exception("GraphCollection has no signature data. Call 'canonicalize' and 'hash' methods first.");
		}
		
		//Get Signature Data
		SignatureData sigData=gc.getSignature();
		
		//Sign
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		
		String signature = new String(
			Base64.encodeBase64(
				cipher.doFinal( sigData.getHash().toByteArray() )
			)
		);
		
		//Update Signature Data
		sigData.setSignature("\""+signature+"\"");
		sigData.setSignatureMethod(privateKey.getAlgorithm().toLowerCase());
		sigData.setVerificationCertificate(verficiationCertificate);
	}

}
