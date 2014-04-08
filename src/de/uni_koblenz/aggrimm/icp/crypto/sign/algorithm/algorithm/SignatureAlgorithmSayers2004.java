package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.algorithm;

import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;

import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.GraphBaseHasher;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.HashCombinator;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.TripleHasher;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.ontology.Ontology;

/**
 * Signature Algorithm "Sayers2004"
 * Ontology Name: sayers-2004
 * 
 * Based on: Sayers, C., Karp, A.H.: Computing the digest of an RDF graph. Technical report, HP Laboratories (2004)
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureAlgorithmSayers2004 implements SignatureAlgorithmInterface {
	private String hasLabel;												//URI for "has Label" labeling predicates
	
	//######################################################## Constructors

	public SignatureAlgorithmSayers2004(){
		//Get sigIri from Ontology
		hasLabel=Ontology.getHasLabelPredicate();
	}
	
	
	//######################################################## Canonicalize
	
	public void canonicalize(GraphCollection gc) throws Exception {
		//Canonicalize all graphs and their sub graphs
		for (NamedGraph g:gc.getGraphs()){
			canonicalizeGraph(g);
		}
		
		//Update Signature Data
		gc.getSignature().setCanonicalizationMethod( Ontology.getCanonicalizationPrefix()+getName() );
	}
	
	/**
	 * Canonicalize graphs (recursive)
	 * 
	 * @param g
	 */
	private void canonicalizeGraph(NamedGraph g){
		//Existing labeling triples (maps blank nodes to label)
		HashMap<String,String> existingLabels=new HashMap<String,String>();
		//New labeling triples (blank nodes and labels are equal for new labeling triples)
		HashSet<String> newLabels = new HashSet<String>();
		//Triples of the current named graph
		ArrayList<Triple> triples=g.getTriples();
		
		//Get existing labeling triples and save them in a hash map
		for (Triple t:triples) {			
			if (t.getPredicate().equals(hasLabel)){
				//Add subjects and objects of labeling triples to vector
				existingLabels.put(t.getSubject(), t.getObject());
			}
		}
		
		//Replace blank node identifiers with identifiers from labeling triples or create new labeling triples
		for (Triple t:triples) {
			//Ignore labeling triples
			if (!t.getPredicate().equals(hasLabel)){	
				//Only scan subject and object position (predicate can't be a blank node)
				for (int i=0; i<=2; i+=2){
					//Blank node detected!
					if (t.getByIndex(i).startsWith("_")){
						//Get label
						String newLabel=existingLabels.get(t.getByIndex(i));
						if (newLabel!=null){
							//Replace blank node with original label (strip quotes from label literal object)
							t.setByIndex(i,newLabel.substring(1,newLabel.length()-1));
						}else{
							//Add new labeling triple
							if (!newLabels.contains(t.getByIndex(i))){
								newLabels.add(t.getByIndex(i));
							}
						}
					}
				}
			}
		}
		
		//Replace blank node identifiers in graph names with identifiers from labeling triples or create new labeling triples
		for (NamedGraph subG:g.getChildren()){
			if (subG.getName().startsWith("_")){
				//Get label
				String newLabel=existingLabels.get(subG.getName());
				if (newLabel!=null){
					//Replace name with original label (strip quotes from label literal object)
					subG.setName(newLabel.substring(1,newLabel.length()-1));
				}else{
					//Add new labeling triple
					if (!newLabels.contains(subG.getName())){
						newLabels.add(subG.getName());
					}
				}
			}
		}
		
		//Add blank node labeling triples (object must be a literal, so add quotes around it)
		for (String label:newLabels) {
			g.addTriple(new Triple(
						label,
						hasLabel,
						"\""+label+"\""
					));
		}
		
		//Sort and canonicalize sub graphs
		Collections.sort(g.getChildren());
		for (NamedGraph subG:g.getChildren()){
			canonicalizeGraph(subG);
		}
	}
	
	public void postCanonicalize(GraphCollection gc){
		//Don't do anything
	}
	
	//######################################################## Hash
	/*
	 * Triples are hashed with Melnik's method.
	 * Graphs / triples are combined with multiplication modulo n.
	 * (same approach is used for hashing in the implementation of Carroll's algorithm)
	 */
	
	public void hash(GraphCollection gc, String digestAlgo) throws Exception {
		//Prepare Digest
		SignatureData sig=gc.getSignature();
		MessageDigest d=MessageDigest.getInstance(digestAlgo);
		sig.setDigestGen(d);
		
		//Hash all graphs and their sub graphs
		sig.setHash(BigInteger.ONE);
		for (NamedGraph g:gc.getGraphs()){
			sig.setHash( HashCombinator.combine( sig.getHash(), hashGraph(g,d), HashCombinator.ca.Multiply ) );
		}
		
		//Update Signature Data
		sig.setGraphDigestMethod( Ontology.getDigestPrefix()+getName() );
	}
	
	/**
	 * Hash graphs (recursive)
	 * 
	 * @param g  {@link NamedGraph} to hash
	 * @param d  used hash method
	 * @return  hash value as byte array
	 * @throws Exception  if hashing failed
	 */
	private BigInteger hashGraph(NamedGraph g, MessageDigest d) throws Exception {		
		//Get graph base hash
		BigInteger h=GraphBaseHasher.calculate(g,d);
		
		//Hash and combine triples
		for (Triple t:g.getTriples()){
			if (Ontology.isRelevantForHash(t)){
				BigInteger tripleHash=TripleHasher.hashTripleMelnik(t, d);
				h=HashCombinator.combine( h, tripleHash, HashCombinator.ca.Multiply );
			}
		}
		
		//Hash and combine sub graphs
		for (NamedGraph subG:g.getChildren()){
			h=HashCombinator.combine( h, hashGraph(subG,d), HashCombinator.ca.Multiply );
		}
		return h;
	}
	
	public void postHash(GraphCollection gc){
		//Don't do anything
	}
	
	//######################################################## Sign
	
	public void sign(GraphCollection gc, Key privateKey, String verificationCertificate) throws Exception {
		Signer.sign(gc, privateKey, verificationCertificate);
	}
	
	//######################################################## Assemble
	
	public void assemble(GraphCollection gc, String signatureGraphName) throws Exception {
		Assembler.assemble(gc, signatureGraphName);
	}
	
	//######################################################## Verify
	
	public boolean verify(GraphCollection gc, Key publicKey) throws Exception {
		return Verifier.verify(gc, publicKey);
	}
	
	//######################################################## Get Name
	
	public String getName(){
		return Ontology.getAlgorithmNameSayers2004();
	}
	
}
