package de.uni_koblenz.aggrimm.icp.crypto.sign.ontology;

import java.security.MessageDigest;
import java.util.LinkedList;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.SignatureData;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.Triple;

/**
 * This class provides an interface to get data from a signature ontology
 * At the moment all values are predefined/hard-coded.
 * An ontology parser could be added later to load the values dynamically from an ontology (e.g.: owl file)
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class Ontology {
	/**
	 * Default prefix for signature statements
	 */
	private String sigPrefix="signature";
	
	private static final String sigIri="http://icp.it-risk.iwvi.uni-koblenz.de/ontologies/signature.owl#";	//IRI for signature statements
	private static final String subjectSigMethod="_:gsm-1";													//Graph Signature Method Subject	
	private static final String subjectSig="_:sig-1";														//Signature Subject

	/**
	 * Signature Data
	 */
	private SignatureData sigData;
	
	/**
	 * Signature Triples
	 */
	private LinkedList<Triple> triples;
	
	private Triple tDigestMethod;
	private Triple tGraphCononicalizationMethod;
	private Triple tGraphDigestMethod;
	private Triple tGraphSerializationMethod;
	private Triple tSignatureMethod;
	
	private Triple tGraphSigningMethod;
	private Triple tSignatureValue;
	private Triple tVerificationCertificate;

	//######################################################## Constructors
	
	public Ontology(){
		this(null);
	}
	
	public Ontology(SignatureData signatureData){
		//Signature Data
		sigData=signatureData;
				
		//Prepare Triples
		triples=new LinkedList<Triple>();
		
		//################### Graph Signature Method Triples
		tDigestMethod = new Triple(getSubjectSigMethod(),getSigPrefix()+":hasDigestMethod","");
		triples.add(tDigestMethod);
		
		tGraphCononicalizationMethod = new Triple(getSubjectSigMethod(),getSigPrefix()+":hasGraphCanonicalizationMethod","");
		triples.add(tGraphCononicalizationMethod);
		
		tGraphDigestMethod = new Triple(getSubjectSigMethod(),getSigPrefix()+":hasGraphDigestMethod","");
		triples.add(tGraphDigestMethod);
		
		tGraphSerializationMethod = new Triple(getSubjectSigMethod(),getSigPrefix()+":hasGraphSerializationMethod","");
		triples.add(tGraphSerializationMethod);
		
		tSignatureMethod = new Triple(getSubjectSigMethod(),getSigPrefix()+":hasSignatureMethod","");
		triples.add(tSignatureMethod);
		
		triples.add(new Triple(getSubjectSigMethod(),"a",getSigPrefix()+":GraphSigningMethod"));
		
		//################### Graph Signature Triples
		tGraphSigningMethod = new Triple(getSubjectSig(),getSigPrefix()+":hasGraphSigningMethod","");
		triples.add(tGraphSigningMethod);
		
		tSignatureValue = new Triple(getSubjectSig(),getSigPrefix()+":hasSignatureValue","");
		triples.add(tSignatureValue);
		
		tVerificationCertificate = new Triple(getSubjectSig(),getSigPrefix()+":hasVerificationCertificate","");
		triples.add(tVerificationCertificate);
		
		triples.add(new Triple(getSubjectSig(),"a",getSigPrefix()+":Signature"));
		
		//################### Set objects if signature data is available
		if (sigData!=null){
			//Graph signature method
			tDigestMethod.setObject(getSigPrefix()+":dm-"+sigData.getDigestGen().getAlgorithm().toLowerCase());
			tGraphCononicalizationMethod.setObject(getSigPrefix()+":"+sigData.getCanonicalizationMethod());
			tGraphDigestMethod.setObject(getSigPrefix()+":"+sigData.getGraphDigestMethod());
			tGraphSerializationMethod.setObject(getSigPrefix()+":gsm-trig");
			tSignatureMethod.setObject(getSigPrefix()+":sm-"+sigData.getSignatureMethod());
			//Graph signature
			tGraphSigningMethod.setObject(getSubjectSigMethod());
			tSignatureValue.setObject(sigData.getSignature());
			tVerificationCertificate.setObject(sigData.getVerificationCertificate());
		}
		
	}
	
	//######################################################## Get signature data from triples
	
	public SignatureData getSignatureDataFromTriples(LinkedList<Triple> sourceTriples) throws Exception{
		//Create empty signature data object
		sigData=new SignatureData();
		
		//Fill with values from triple
		for (Triple t:sourceTriples){
			String predicate=t.getPredicate();
			String object=t.getObject();
			int offset;
			
			//Digest method (low level string hashing): dm-md5 / dm-sha1
			if (predicate.equals("<"+sigIri+"hasDigestMethod>")){
				offset=object.indexOf("#dm-");
				if (offset>0){
					String digestName=object.substring(offset+4, object.length()-1);
					sigData.setDigestGen( MessageDigest.getInstance(digestName) );
				}
				
			//Canonicalization method: gcm-carroll-2003 / gcm-fisteus-2010 / gcm-sayers-2004
			}else if (predicate.equals("<"+sigIri+"hasGraphCanonicalizationMethod>")){
				offset=object.indexOf("#");
				if (offset>0){
					sigData.setCanonicalizationMethod( object.substring(offset+1, object.length()-1) );
				}
			
			//Digest method: gdm-carroll-2003 / gdm-fisteus-2010 / gdm-melnik-2001 / gdm-sayers-2004 
			}else if (predicate.equals("<"+sigIri+"hasGraphDigestMethod>")){
				offset=object.indexOf("#");
				if (offset>0){
					sigData.setGraphDigestMethod( object.substring(offset+1, object.length()-1) );
				}
			
			//Graph serialization: gsm-n-triples / gsm-n3 / gsm-owl-xml / gsm-rdf-xml / gsm-trig / gsm-turtle
			}else if (predicate.equals("<"+sigIri+"hasGraphSerializationMethod>")){
				offset=object.indexOf("#");
				if (offset>0){
					sigData.setSerializationMethod( object.substring(offset+1, object.length()-1) );
				}
				
			//Signature method: sm-dsa / sm-elgamal / sm-rsa
			}else if (predicate.equals("<"+sigIri+"hasSignatureMethod>")){
				offset=object.indexOf("#");
				if (offset>0){
					sigData.setSignatureMethod( object.substring(offset+1, object.length()-1) );
				}
							
			//Graph signing method: Reference to gsm triple
			}else if (predicate.equals("<"+sigIri+"hasGraphSigningMethod>")){
				//found automatically by IRI
				
			//Signature value
			}else if (predicate.equals("<"+sigIri+"hasSignatureValue>")){
				if (object.length()>=2){
					sigData.setSignature( object.substring(1, object.length()-1) );
				}
				
			//Signature certificate
			}else if (predicate.equals("<"+sigIri+"hasVerificationCertificate>")){
				//Certificate for verification must be passed manually at the moment
				//This could be used to get/download the certificate automatically somehow
			}
			
		}
		
		return sigData;
	}

	
	//######################################################## Basic Getters & Setters
	
	public static String getSigIri() {
		return sigIri;
	}
	
	public String getSigPrefix() {
		return sigPrefix;
	}
	
	public void setSigPrefix(String sigPrefix) {
		this.sigPrefix = sigPrefix;
	}
	
	public String getSubjectSigMethod() {
		return subjectSigMethod;
	}
	
	public String getSubjectSig() {
		return subjectSig;
	}
	
	public LinkedList<Triple> getTriples(){
		return triples;
	}
	
	public LinkedList<Triple> getTriplesWithoutSignature(){
		LinkedList<Triple> r=new LinkedList<Triple>();
		for (Triple t:triples){
			if (!t.getPredicate().equals(tGraphSigningMethod.getPredicate())){
				if (!t.getPredicate().equals(tSignatureValue.getPredicate())){
					if (!t.getPredicate().equals(tVerificationCertificate.getPredicate())){
						if (!t.getObject().equals(getSigPrefix()+":Signature")){
							r.add(t);
						}
					}
				}
			}
		}
		return r;
	}
	
	public void setSigData(SignatureData sigData){
		this.sigData = sigData;
	}
	
	public static String getTypeSignature(){
		return "Signature";
	}
	
	public static String getTypeGraphSigningMethod(){
		return "GraphSigningMethod";
	}
	
	//######################################################## W3C Getters
	
	//W3C Prefix
	public static String getW3CSyntaxPrefix(){
		return "rdf";
	}
	
	//W3C URI
	public static String getW3CSyntaxURI(){
		return "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
	}
	
	
	//######################################################## Algorithm Specific Getters
	
	//Labeling predicate (used by Sayers2004)
	public static String getHasLabelPredicate(){
		return "<http://icp.it-risk.iwvi.uni-koblenz.de/ontologies/signature.owl#hasLabel>";
	}
	
	//C14N Prefix (used by Carroll2003)
	public static String getC14NPrefix(){
		return "c14n";
	}
	
	//C14N URI (used by Carroll2003)
	public static String getC14NURI(){
		return "<http://www-uk.hpl.hp.com/people/jjc/rdf/c14n#>";
	}
	
	//C14N Predicate (used by Carroll2003)
	public static String getC14NPredicate(){
		return "<http://www-uk.hpl.hp.com/people/jjc/rdf/c14n#true>";
	}
	
	
	//Tummarello Signature Prefix (used by Tummarello2005)
	public static String getTummarelloSignaturePrefix(){
		return "dbin";
	}
	
	//Tummarello Signature URI (used by Tummarello2005)
	public static String getTummarelloSignatureURI(){
		return "http://dbin.org#";
	}

	//Tummarello Signature Text (used by Tummarello2005)
	public static String getTummarelloSignatureText(){
		return "Base64SigValue";
	}	
	
	//Tummarello Certificate Text (used by Tummarello2005)
	public static String getTummarelloCertificateText(){
		return "PGPCertificate";
	}
	
	//Tummarello Reification Blank Node Prefix (used by Tummarello2005)
	public static String getReificationBNPrefix(){
		return "reific";
	}
	
	//######################################################## Algorithm Descriptions
	
	//Graph Canonicalization Method Prefix
	public static String getCanonicalizationPrefix(){
		return "gcm-";
	}
	
	//Graph Digest Method Prefix
	public static String getDigestPrefix(){
		return "gdm-";
	}
	
	//Carroll 2003
	public static String getAlgorithmNameCarroll2003(){
		return "carroll-2003";
	}

	//Fisteus 2010
	public static String getAlgorithmNameFisteus2010(){
		return "fisteus-2010";
	}
	
	//Sayers 2004
	public static String getAlgorithmNameSayers2004(){
		return "sayers-2004";
	}
	
	//Tummarello 2005
	public static String getAlgorithmNameTummarello2005(){
		return "tummarello-2005";
	}
	
	
	//######################################################## Other functions
	
	/**
	 * Is triple relevant for hash or will it be ignored in hash calculation?
	 * 
	 * @param t  triple to examine
	 * @return  true if relevant for hash, false if not
	 */
	public static boolean isRelevantForHash(Triple t){
		String predicate=t.getPredicate();
				
		//Sayers2004: Labeling predicate
		if (predicate.equals(getHasLabelPredicate())){
			return false;
		}
		
		//All other cases: Relevant!
		return true;
	}
	
}
