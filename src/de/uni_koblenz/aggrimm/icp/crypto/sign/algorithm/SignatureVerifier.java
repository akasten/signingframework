package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.ontology.Ontology;
import de.uni_koblenz.aggrimm.icp.crypto.sign.trigplus.TriGPlusReader;

/**
 * Automatically performs all steps for a signature verification.
 * Detects required algorithms and settings by reading the signature data.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureVerifier {

	/**
	 * Verify a file using a public key
	 * 
	 * @param path path to a file containing graph data
	 * @param publicKey a public key for signature verification
	 * @return  true if successfully verified, false otherwise
	 */
	public static boolean verify(String path, Key publicKey) throws Exception{
		//Load and parse file
		GraphCollection gc=TriGPlusReader.readFile(path,true);
		
		//Verify
		return verify(gc, publicKey);
	}
	
	/**
	 * Verify a file using a X.509 certificate
	 * 
	 * @param path path to a file containing graph data
	 * @param publicKey a public key for signature verification
	 * @return  true if successfully verified, false otherwise
	 */
	public static boolean verify(String path, X509Certificate cert) throws Exception{
		//Load and parse file
		GraphCollection gc=TriGPlusReader.readFile(path,true);
		
		//Get Key
		Key publicKey=cert.getPublicKey();
		
		//Verify
		return verify(gc, publicKey);
	}
	
	
	/**
	 * Verify graph collection using a X.509 certificate
	 * 
	 * @param path path to a file containing graph data
	 * @param publicKey a public key for signature verification
	 * @return  true if successfully verified, false otherwise
	 */
	public static boolean verify(GraphCollection gc, X509Certificate cert) throws Exception {
		Key publicKey=cert.getPublicKey();
		return verify(gc, publicKey);
	}
	
	/**
	 * Verify a graph collection using a public key
	 * A graph collection can only be verified if it contains just a signature graph at root level and nothing else!
	 * 
	 * @param path path to a file containing graph data
	 * @param publicKey a public key for signature verification
	 * @return  true if successfully verified, false otherwise
	 * @throws Exception  if full verification failed
	 */
	public static boolean verify(GraphCollection gc, Key publicKey) throws Exception{		
		//Ontology Data
		Ontology o=new Ontology();
		String sigIri=Ontology.getSigIri();		//Get signature IRI
		
		//Find signature graphs and signature statements
		String w3ctype="<"+Ontology.getW3CSyntaxURI()+"type>";
		NamedGraph newRoot=null;
		LinkedList<Triple> sigList=new LinkedList<Triple>();
		int signedGraphs=0;
		int unsignedGraphs=0;
		for (NamedGraph g:gc.getGraphs()){
			if (g.getDepth()==-1){
				//No statements at root level allowed!
				if (!g.getTriples().isEmpty()){
					throw new Exception("Failed to verify: " +
							"Graph contains statements at root level (outside signature graph). " +
							"A successful verificaton of contained signed graphs would not ensure the integrity and authenticity of all data. ");
				}
				
			}else{
				//Search for signature data and cache all triples which might be part of the signature in a list
				String signatureID="";
				String graphSigningMethodID="";
				LinkedList<Triple> tempSigList=new LinkedList<Triple>();
				for (Triple t:g.getTriples()){
					//Signature statements contain the signature IRI either as part of the predicate or object
					if (t.getPredicate().startsWith("<"+sigIri) || t.getObject().startsWith("<"+sigIri)){
						//Labeling statements are not part of the signature though
						if (!t.getPredicate().equals(Ontology.getHasLabelPredicate())){
							//Add all to a temp list
							tempSigList.add(t);
							
							//Detect types "Signature" and "graphSigningMethod" which link to signature statements
							if (t.getPredicate().equals(w3ctype)){
								if (t.getObject().equals("<"+Ontology.getSigIri()+Ontology.getTypeSignature()+">")){
									signatureID=t.getSubject();
								} else if (t.getObject().equals("<"+Ontology.getSigIri()+Ontology.getTypeGraphSigningMethod()+">")){
									graphSigningMethodID=t.getSubject();
								}
							}
						}
					}
				}
				
				//Is this a signature graph? (at least "graphSigningMethod" statements must be present)
				if ( graphSigningMethodID.length()>0 ){
					//Yes, this is a signature graph
					signedGraphs++;
					
					//Filter signature statements by searching for appropriate identifiers
					if (newRoot==null){
						newRoot=g;
						sigList=new LinkedList<Triple>();
						for (Triple t:tempSigList){
							if ( t.getSubject().equals(signatureID) || t.getSubject().equals(graphSigningMethodID) ){
								sigList.add(t);
							}
						}
					}	
				}else{
					//This is no signature graph
					unsignedGraphs++;
				}
				
				tempSigList.clear();
			}
		}
		
		//Is a complete verification of the provided data possible?
		if (sigList.isEmpty() || newRoot==null){
			//No, no signature graph with signature statements found
			throw new Exception("Failed to verify: " +
					"No signature statements found. " +
					"Data seems to be unsigned or damaged/manipulated. ");
		}
		if (signedGraphs>1){
			//No, there are multiple signature graphs. Which one to check?!
			throw new Exception("Failed to verify: " +
					signedGraphs+" signed graphs at root level detected. " +
					"Do not know which one to verify. ");
		}
		if (unsignedGraphs>0){
			//No, unsigned graphs at root level.
			throw new Exception("Failed to verify: " +
					unsignedGraphs+" unsigned graph(s) at root level detected. " +
					"A successful verificaton of signed graphs would not ensure the integrity and authenticity of all data. ");
		}
		
		//Handle Signature Triples and get signature data
		SignatureData sigData=o.getSignatureDataFromTriples(sigList);
		gc.setSignature(sigData);
		
		//Kill signature triples
		for (Triple kill:sigList){
			newRoot.removeTriple(kill);
		}
		
		//Change graphs (remove signature graph)
		gc.setGraphs(newRoot.getChildren());									//Children of signature graph are new root children
        NamedGraph rootGraph=new NamedGraph("",-1,null);						//Create new root graph
        gc.getGraphs().add(rootGraph);											//Add root graph to graph collection
        for (Triple t:newRoot.getTriples()){
        	rootGraph.addTriple(t);												//Add triples of signature graph (except signature triples) to root graph
        }
        gc.updateDepths();
        
        //Get Algorithm List
        LinkedList<SignatureAlgorithmInterface> list=SignatureAlgorithmList.getList();	//List of all existing signature algorithms
        
        //Get algorithms
        SignatureAlgorithmInterface canonicalizationAlgorithm=null;				//Algorithm used for canonicalization
        SignatureAlgorithmInterface hashingAlgorithm=null;						//Algorithm used for hashing
        for (SignatureAlgorithmInterface a:list){
        	//Get canonicalization algorithm
        	if ( (Ontology.getCanonicalizationPrefix()+a.getName()).equals( sigData.getCanonicalizationMethod() ) ){
        		canonicalizationAlgorithm=a;
        	}
        	//Get hashing algorithm
        	if ( (Ontology.getDigestPrefix()+a.getName()).equals( sigData.getGraphDigestMethod() ) ){
        		hashingAlgorithm=a;
        	}
        }
        
        //Canonicalize
        if (canonicalizationAlgorithm!=null){
        	canonicalizationAlgorithm.canonicalize(gc);
        	canonicalizationAlgorithm.postCanonicalize(gc);
        }else{
        	throw new Exception("No algorithm found for graph canoncialization method '"+sigData.getCanonicalizationMethod()+"'");
        }
        
        //Hash
        if (hashingAlgorithm!=null){
        	hashingAlgorithm.hash(gc, sigData.getDigestGen().getAlgorithm().toLowerCase() );
        	hashingAlgorithm.postHash(gc);
        }else{
        	throw new Exception("No algorithm found for graph digest method '"+sigData.getGraphDigestMethod()+"'");
        }
        
        //Verify (use method of hashing algorithm)
        return hashingAlgorithm.verify(gc, publicKey);
	}
	
	/**
	 * Resets a graph collection after a verification
	 * Removes all temporary hash and signature values
	 * Removes MSGs and converts them back to triple representation without MSGs
	 * 
	 * @param gc
	 */
	public static void resetAfterVerification(GraphCollection gc){
		//Remove signature data
		gc.setSignature(null);
		
		//Reset graphs
		for (NamedGraph g:gc.getGraphs()){
			resetGraphAfterVerification(g);
		}
	}
	
	private static void resetGraphAfterVerification(NamedGraph g){
		//Merge MSGs
		g.mergeMSGs();
		
		//Clear graph data
		g.setVariableHashes(null);
		if (g.getMSGSignatures()!=null){
			g.getMSGSignatures().clear();
		}
		
		//Clear triple data
		for (Triple t:g.getTriples()){
			t.setHash(null);
		}
		
		//Children
		for (NamedGraph subG:g.getChildren()){
			resetGraphAfterVerification(subG);
		}
	}
	
}
