package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic;

import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.GraphCollection;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.SignatureData;

/**
 * Standard {@link GraphCollection} verifier
 *
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class Verifier {
	
	/**
	 * Verifies a {@link GraphCollection} using a public key
	 * 
	 * @param gc			{@link GraphCollection} to sign
	 * @param publicKey 	a public key for signature verification
	 * @return				true if verification succeeded, false otherwise
	 * @throws Exception
	 */
	public static boolean verify(GraphCollection gc, Key publicKey) throws Exception{
		SignatureData sigData = gc.getSignature();
		
    	//Decrypt signature using the provided public key
		Cipher cipher = Cipher.getInstance( publicKey.getAlgorithm() );
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		String sigString = sigData.getSignature();
		if (sigString==null){
			throw new Exception("Signature value not found");
		}
		if (sigString.length()==0){
			throw new Exception("Signature value is empty");
		}
		
		//Decrypt
		byte [] sigDecrypted = null;
		try {
			sigDecrypted=cipher.doFinal(
				Base64.decodeBase64(sigString)
			);
		} catch (Exception e){
			return false;
		}
		
		//Are sigDecrypted and hash equal?
		byte[] hash=sigData.getHash().toByteArray();
		return (Arrays.equals(sigDecrypted,hash));
	}
	
}
