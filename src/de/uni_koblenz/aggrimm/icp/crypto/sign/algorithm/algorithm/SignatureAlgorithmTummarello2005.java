package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.algorithm;

import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Iterator;
import java.util.ArrayList;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic.Assembler;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.ontology.Ontology;

/**
 * Signature Algorithm "Tummarello2005"
 * Ontology Name: tummarello-2005
 *
 * Based on: Tummarello, G., Morbidoni, C., Puliti, P., Piazza, F.: Signing individual fragments of an RDF graph. In: WWW, ACM (2005) 1020-1021
 * Uses the algorithm of Carroll (see class SignatureAlgorithmCarroll2003)
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureAlgorithmTummarello2005 implements SignatureAlgorithmInterface {
	//W3C Syntax Triple Data
	private static String w3cRdfSyntaxPrefix=Ontology.getW3CSyntaxPrefix();
	private static String w3cRdfSyntaxUri=Ontology.getW3CSyntaxURI();
	
	//MSG Signature (DBin) Triple Data
	private static String signaturePrefix=Ontology.getTummarelloSignaturePrefix();
	private static String signatureUri=Ontology.getTummarelloSignatureURI();
	private static String signatureText=Ontology.getTummarelloSignatureText();
	private static String certificateText=Ontology.getTummarelloCertificateText();
	
	//Blank Node Prefix
	private static final String blankNodePrefix=Ontology.getReificationBNPrefix();
	
	//Carroll algorithm (used for canonicalization/hashing)
	private SignatureAlgorithmCarroll2003 carroll;
	
	//######################################################## Constructors

	public SignatureAlgorithmTummarello2005(){
		//Initialize Carroll's algorithm
		carroll=new SignatureAlgorithmCarroll2003();
	}
	
	
	//######################################################## Canonicalize
	
	public void canonicalize(GraphCollection gc) throws Exception {		
		//Canonicalize graphs (recursive)
		for (NamedGraph g:gc.getGraphs()){
			canonicalizeGraph(g);
		}
				
		//Add prefixes
		carroll.addC14NPrefix(gc);
		gc.addPrefix(new Prefix(w3cRdfSyntaxPrefix+":","<"+w3cRdfSyntaxUri+">"));
		gc.addPrefix(new Prefix(signaturePrefix+":","<"+signatureUri+">"));
		
		//Update Signature Data
		gc.getSignature().setCanonicalizationMethod( Ontology.getCanonicalizationPrefix()+getName() );
	}
	
	/**
	 * Canonicalize graphs by caching and removing reification statements & applying algorithm of Carroll (recursive)
	 * 
	 * @param g
	 * @throws Exception  if incomplete reifications are detected
	 */
	private void canonicalizeGraph(NamedGraph g) throws Exception{
		ArrayList<Triple> triples=g.getTriples();
		
		//Find existing reification statements
		ArrayList<String> reifications=new ArrayList<String>();
		Iterator<Triple> it = triples.iterator();
		while (it.hasNext()) {
			Triple t=it.next();
			if (t.getSubject().startsWith("_")){
				if (t.getObject().equals("<"+w3cRdfSyntaxUri+"Statement>")){
					if (t.getPredicate().equals("<"+w3cRdfSyntaxUri+"type>")){
						reifications.add(t.getSubject());
						it.remove();
					}
				}
			}
		}
		
		//Save and remove existing reification statements
		if (!reifications.isEmpty()){
			for (String reificationSubject:reifications){
				it = triples.iterator();
				String[] data=new String[5];
				while (it.hasNext()) {
					//Detect & Remove
					Triple t=it.next();
				    if (t.getSubject().equals(reificationSubject)) {
				    	//data[0] <- Reification Subject
				    	if (t.getPredicate().equals("<"+w3cRdfSyntaxUri+"subject>")){
				    		data[0]=t.getObject();
				    	//data[1] <- Reification Predicate
				    	}else if (t.getPredicate().equals("<"+w3cRdfSyntaxUri+"predicate>")){
				    		data[1]=t.getObject();
				    	//data[2] <- Reification Object
				    	}else if (t.getPredicate().equals("<"+w3cRdfSyntaxUri+"object>")){
				    		data[2]=t.getObject();
				    	//data[3] <- Reification Certificate
				    	}else if (t.getPredicate().equals("<"+signatureUri+certificateText+">")){
				    		data[3]=t.getObject();
				    	//data[4] <- Reification Signature
				    	}else if (t.getPredicate().equals("<"+signatureUri+signatureText+">")){
				    		data[4]=t.getObject();
				    	//Everything else...
				    	}else{
				    		//Unexpected, additional reification statemens should not cause any problems
				    		//Could throw an exception when being strict though
				    		throw new Exception("Unexpected reification statement: "+t);
				    	}
				    	//Remove
		    			it.remove();
				    }
				}
				//Check if reification is complete (are subject, predicate, object, certificate and signature set?) 
				if (!Arrays.asList(data).contains(null)){
					g.addMSGSignature(data);
				}else{
					throw new Exception("Incomplete reification: "+Arrays.toString(data));
				}
			}
		}
		
		//Apply Carroll's canonicalization
		if (!triples.isEmpty()){
			carroll.nondeterministicPreCanonicalization(g);
		}
		
		//Canonicalize sub graphs
		for (NamedGraph subG:g.getChildren()){
			canonicalizeGraph(subG);
		}
	}
	
	public void postCanonicalize(GraphCollection gc){
		//Split graphs into MSGs (recursive)
		for (NamedGraph g:gc.getGraphs()){
			g.splitIntoMSGs();
		}
	}
	
	//######################################################## Hash
	
	public void hash(GraphCollection gc, String digestAlgo) throws Exception {
		//Prepare Digest
		SignatureData sig=gc.getSignature();
		MessageDigest d=MessageDigest.getInstance(digestAlgo);
		sig.setDigestGen(d);
		
		//Hash the MSGs of all graphs
		for (NamedGraph g:gc.getGraphs()){
			hashGraph(g,d);
		}
		
		//Update Signature Data
		sig.setGraphDigestMethod( Ontology.getDigestPrefix()+getName() );
	}
	
	/**
	 * Hash named graphs (recursive) by calculating the hash values for all individual MSGs in each graph
	 * 
	 * @param g
	 * @param d
	 * @throws Exception
	 */
	private void hashGraph(NamedGraph g, MessageDigest d) throws Exception {	
		//Hash MSGs
		for (MSG msg:g.getMSGs()){
			hashMSG(msg, d);
		}
		
		//Hash sub graphs
		for (NamedGraph subG:g.getChildren()){
			hashGraph(subG,d);
		}
	}
	
	/**
	 * Hash MSG by hashing all triples in the MSG using the method of Carroll
	 * 
	 * @param msg
	 * @param d
	 * @throws Exception
	 */
	private void hashMSG(MSG msg, MessageDigest d) throws Exception {
		BigInteger h=BigInteger.ONE;
		h=carroll.hashTriples(h,msg.getTriples(),d);
		msg.setHash(h);
	}
	
	public void postHash(GraphCollection gc){
		//Don't do anything
	}

	//######################################################## Sign
	
	public void sign(GraphCollection gc, Key privateKey, String verficiationCertificate) throws Exception {
		//Sign all MSGs in all graphs and sub graphs
		for (NamedGraph g:gc.getGraphs()){
			signGraph(g, privateKey, verficiationCertificate);
		}
		
		//Update Signature Data
		gc.getSignature().setSignatureMethod(privateKey.getAlgorithm().toLowerCase());
	}
	
	/**
	 * Sign named graphs (recursive) by signing each individual MSG in it
	 * 
	 * @param g
	 * @param privateKey
	 * @param verficiationCertificate
	 * @throws Exception  if graph has not been split to MSGs properly
	 */
	private void signGraph(NamedGraph g, Key privateKey, String verficiationCertificate) throws Exception {
		//Has triples? Shouldn't be the case. There should only be MSGs!
		if (!g.getTriples().isEmpty()){
			throw new Exception("Graph has triples which are not split into MSGs. Call 'canonicalize' of Tummarello2005 first.");
		}
		
		//Sign MSGs
		for (MSG msg:g.getMSGs()){
			signMSG(msg, privateKey, verficiationCertificate);
		}
		
		//Sign sub graphs
		for (NamedGraph subG:g.getChildren()){
			signGraph(subG, privateKey, verficiationCertificate);
		}
	}
	
	/**
	 * Sign MSG
	 * 
	 * @param msg
	 * @param privateKey
	 * @param verficiationCertificate
	 * @throws Exception  if MSG has no hash data because no hashing has been performed
	 */
	private void signMSG(MSG msg, Key privateKey, String verficiationCertificate) throws Exception {
		//Signature Data existing?
		if (msg.getHash()==null){
			throw new Exception("MSG has no hash data. Call 'canonicalize' and 'hash' methods first.");
		}
				
		//Sign
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		String signature = new String( Base64.encodeBase64( cipher.doFinal( msg.getHash().toByteArray() ) ));
		//String signature = new String( Base64.encodeBase64( msg.getHash().toByteArray() ) );
		
		//Update Signature Data
		msg.setSignature( signature );
		msg.setCertificate( verficiationCertificate );
	}
	
	//######################################################## Assemble
	
	public void assemble(GraphCollection gc, String signatureGraphName) throws Exception {
		//Assemble all MSGs in all graphs and sub graphs
		for (NamedGraph g:gc.getGraphs()){
			assembleGraph(g);
		}
		
		//Add Signature Graph
		Assembler.assemble(gc, signatureGraphName, false);
	}
	
	/**
	 * Assemble graph MSGs (recursive) by adding 4 reification statements + 2 signature statements per MSG 
	 * 
	 * @param g
	 */
	private void assembleGraph(NamedGraph g){
		//Add signature data to all MSGs in this graph using reification
		int bnIndex=0;
		for (MSG msg:g.getMSGs()){
			ArrayList<Triple> triples=msg.getTriples();
			//Only care about non empty MSGs
			if (!triples.isEmpty()){
				//Get first statement
				Triple first=triples.get(0);
				//Get blank node identifier
				bnIndex++;
				String bnID="_:"+blankNodePrefix+bnIndex;
				//Add reification statements
				triples.add(new Triple(bnID, "<"+w3cRdfSyntaxUri+"type>", "<"+w3cRdfSyntaxUri+"Statement>"));
				triples.add(new Triple(bnID, "<"+w3cRdfSyntaxUri+"subject>", first.getSubject()));
				triples.add(new Triple(bnID, "<"+w3cRdfSyntaxUri+"predicate>", first.getPredicate()));
				triples.add(new Triple(bnID, "<"+w3cRdfSyntaxUri+"object>", first.getObject()));
				//Add signature statements
				triples.add(new Triple(bnID, "<"+signatureUri+certificateText+">", msg.getCertificate()));
				triples.add(new Triple(bnID, "<"+signatureUri+signatureText+">", "\""+msg.getSignature()+"\"" ));
			}
		}
		
		//Assemble sub graphs
		for (NamedGraph subG:g.getChildren()){
			assembleGraph(subG);
		}
	}
	
	//######################################################## Verify
	
	public boolean verify(GraphCollection gc, Key publicKey) throws Exception {
		//Verify all MSGs in all graphs and sub graphs
		for (NamedGraph g:gc.getGraphs()){
			if (!verifyGraph(g, publicKey)){
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Verify a named graph (recursive) by verifying each individual MSG in it
	 * 
	 * @param g  {@link NamedGraph} to verifiy
	 * @param publicKey  public key used for cryptographic signature verificaton
	 * @return  true if successfully verified, false otherwise
	 * @throws Exception  if signatures are missing or if there are signatures for removed MSGs
	 */
	private boolean verifyGraph(NamedGraph g, Key publicKey) throws Exception {
		ArrayList<String[]> msgSigs=g.getMSGSignatures();
		
		//Verify all MSGs
		for (MSG msg:g.getMSGs()){
			ArrayList<Triple> triples=msg.getTriples();
			//Ignore empty MSGs
			if (!triples.isEmpty()){
				
				//Assign cached signatures to corresponding MSGs
				if (msgSigs!=null){
					Iterator<String[]> it = msgSigs.iterator();
					while (it.hasNext()) {
						String[] msgSig=it.next();
						if (msg.containsTriple(new String[]{msgSig[0],msgSig[1],msgSig[2]})){
							msg.setCertificate(msgSig[3]);
							msg.setSignature(msgSig[4]);
							it.remove();
							break;
						}
					}
				}
				
				//Check Signature
				String sigString=msg.getSignature();
				BigInteger sigHash=msg.getHash();
				if (sigString!=null && sigHash!=null){
					//Strip Quotes
					sigString=sigString.substring(1, sigString.length()-1);
					
			    	//Decrypt signature using the provided public key
					Cipher cipher = Cipher.getInstance( publicKey.getAlgorithm() );
					cipher.init(Cipher.DECRYPT_MODE, publicKey);
					
					//Decrypt
					byte [] sigDecrypted = null;
					try {
						sigDecrypted=cipher.doFinal( Base64.decodeBase64( sigString ));
					} catch (Exception e){
						return false;
					}
					
					//Are sigDecrypted and hash equal?
					byte [] hash=sigHash.toByteArray();
					if (!Arrays.equals(sigDecrypted,hash)){
						return false;
					}
					
				}else{
					throw new Exception("No signature/hash found for MSG:\n"
							+msg
							+" \n"
							+g);
				}
				
			}
		}
		
		//Unused MSG Signatures?
		//This is a sign for removed MSGs/triples
		if (msgSigs.size()>0){
			for (String[] msgSig:msgSigs){
				throw new Exception("Unused MSG reification signature detected. "
						+"Probably due to MSG/triple removal after signing:\n"
						+"Reification: "+msgSig[0]+" "+msgSig[1]+" "+msgSig[2]+"\n"
						+"Cert: "+msgSig[3]+"\n"
						+"Sig: "+msgSig[4]+"\n"
						);
			}
		}
		
		//Verify MSGs in sub graphs
		for (NamedGraph subG:g.getChildren()){
			if (!verifyGraph(subG, publicKey)){
				return false;
			}
		}
		
		return true;
	}
	
	//######################################################## Get Name
	
	public String getName() {
		return Ontology.getAlgorithmNameTummarello2005();
	}

}
