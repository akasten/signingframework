package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * SignatureData is used to keep track of all relevant signature data which belongs to a graph collection.
 * This includes the actual hash and signature and information about the used algorithms/settings.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureData {
	//Variable								  Description								Saved in signed file as
	private BigInteger hash;				//Hash										- unsaved -
	private String signature;				//Signature (string representation)			hasSignatureValue
	private MessageDigest digestGen;		//Digest generator							hasDigestMethod (indirectly)
	private String canonicalizationMethod;	//Canonicalization method					hasGraphCanonicalizationMethod
	private String graphDigestMethod;		//Graph digest/hashing method				hasGraphDigestMethod
	private String serializationMethod;		//Graph serialization						hasGraphSerializationMethod
	private String signatureMethod;			//Signature method							hasSignatureMethod
	private String verificationCertificate;	//Signature verification certificate		hasVerificationCertificate
	
	//######################################################## Getters & Setters
	
	public BigInteger getHash() {
		return hash;
	}

	public void setHash(BigInteger hash) {
		this.hash = hash;
	}
	
	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public MessageDigest getDigestGen() {
		return digestGen;
	}

	public void setDigestGen(MessageDigest digestGen) {
		this.digestGen = digestGen;
	}
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	public void setCanonicalizationMethod(String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	public String getGraphDigestMethod() {
		return graphDigestMethod;
	}

	public void setGraphDigestMethod(String graphDigestMethod) {
		this.graphDigestMethod = graphDigestMethod;
	}
	
	public String getSerializationMethod() {
		return serializationMethod;
	}

	public void setSerializationMethod(String serializationMethod) {
		this.serializationMethod = serializationMethod;
	}

	public String getSignatureMethod() {
		return signatureMethod;
	}

	public void setSignatureMethod(String signatureMethod) {
		this.signatureMethod = signatureMethod;
	}
	
	public String getVerificationCertificate() {
		return verificationCertificate;
	}

	public void setVerificationCertificate(String verficiationCertificate) {
		this.verificationCertificate = verficiationCertificate;
	}
	
}
