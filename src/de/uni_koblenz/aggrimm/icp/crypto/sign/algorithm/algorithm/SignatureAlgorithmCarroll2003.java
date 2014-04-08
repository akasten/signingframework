package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.algorithm;

import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.ArrayList;

import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.GenSymCounter;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.GraphBaseHasher;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.HashCombinator;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.ontology.Ontology;

/**
 * Signature Algorithm "Carroll2003"
 * Ontology Name: carroll-2003
 * 
 * Based on: Carroll, J.J.: Signing RDF graphs. In: ISWC 2003, Springer (2003) 369-384
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureAlgorithmCarroll2003 implements SignatureAlgorithmInterface {
	private int bnCount;																	//Count of blank nodes (substituteBlankNodes)
	private HashMap<String,Integer> lookupTable;											//Table holds new names for blank nodes (nondeterministicPreCanonicalization)
	private GenSymCounter counter;															//Blank node symbol generator counter (nondeterministicPreCanonicalization)	
	
	//######################################################## Canonicalize
	
	public void canonicalize(GraphCollection gc) throws Exception {		
		//Canonicalize all graphs and their sub graphs
		for (NamedGraph g:gc.getGraphs()){
			canonicalizeGraph(g);
		}
		
		//Add c14n prefix
		addC14NPrefix(gc);
		
		//Update Signature Data
		gc.getSignature().setCanonicalizationMethod( Ontology.getCanonicalizationPrefix()+getName() );
	}
	
	/**
	 * Canonicalize graphs (recursive)
	 * 
	 * @param g  {@link NamedGraph} to canonicalize
	 * @throws Exception
	 */
	private void canonicalizeGraph(NamedGraph g) throws Exception{
		//Canonicalize
		nondeterministicPreCanonicalization(g);
		//Canonicalize sub graphs
		for (NamedGraph subG:g.getChildren()){
			canonicalizeGraph(subG);
		}
	}
	
	/**
	 * Prepares blank nodes by replacing them with "~".
	 * Counts them and puts the original identifiers into annotations.
	 * Only subject OR object can be replaced at once because the annotation can only save one identifier
	 * 
	 * @param triples  triples to prepare
	 */
	private void substituteBlankNodes(ArrayList<Triple> triples){
		//Replace blank nodes with "~" so blank node identifiers are ignored during sorting
		//Save their original names as annotation (annotations will be ignored during sorting as well)
		bnCount = 0;
		for(Triple t:triples) {
			if (t.getSubject().startsWith("_")){
				//Subject is a blank node - replace with "~"
				t.setAnnotation(t.getSubject());
				t.setSubject("~");
				//Increase counter
				if (t.getObject().startsWith("_")){
					bnCount+=2;
				}else{
					bnCount++;
				}
			}else if (t.getObject().startsWith("_")){
				//Object is a blank node - replace with "~"
				t.setAnnotation(t.getObject());
				t.setObject("~");
				//Increase counter
				bnCount++;
			}
		}
	}
	
	/**
	 * Performs one-step deterministic labeling.
	 * Note: Call substituteBlankNodes before calling this function the first time.
	 *
	 * Steps:
	 * 1) Sort all triples
	 * 2) Find and assign new identifiers for blank nodes
	 * 3) Sort all triples again
	 * 
	 * @paramg g  {@link NamedGraph} to canonicalize
	 * @throws Exception
	 */
	private void oneStepDeterministicLabelling(NamedGraph g) throws Exception{
		//Sort triples
		ArrayList<Triple> triples=g.getTriples();
		Collections.sort(triples);
		
		//Find new names for "~" (formerly blank nodes)
		//This is done by iterating over all triples TWICE
		// - First iteration: Skip triples which are equal to the previous or next triple, rename "~" by enumerating them (new names: "_:gX")
		// - Second iteration: Check all triples, rename "~" if their old name has been found and replaced in the first iteration already
		int tripleCount = triples.size();											//Number of triples
		String bnName;																//Blank node name
		Triple current;																//Triple which will be examined
		//Iterate over all triples twice
		for (int i=0; i<2; i++){		
			//Iterate over all triples			
			for (int j=0; j<tripleCount; j++ ){
				//Get triple which will be examined
				current = triples.get(j);
				
				//Only in first iteration:
				//Check if this triple's subject, predicate and object are equal to previous or next triple's
				//Continue with next triple if this is the case
				if (i == 0){
					if (j > 0){
						if ( current.isSPOequal( triples.get(j-1) ) ){
							continue;
						}
					}
					if ((j+1) < tripleCount){
						if ( current.isSPOequal( triples.get(j+1) ) ){
							continue;
						}
					}
				}
				
				//Object and subject replacement - two iterations in while loop:
				// 1) pos = Triple.object
				// 2) pos = Triple.subject
				int pos = Triple.object;
				while (true){
					if (current.getByIndex(pos).equals("~")){
						//Get original blank node identifier from annotation
						bnName = current.getAnnotation();
						//Is blank node in lookup table?
						Integer lookupName = lookupTable.get(bnName);
						if (lookupName != null){
							//Yes, use value from lookup table for name
							current.setByIndex(pos, "_:g"+counter.createSymStringFromInt(lookupName));
							current.setAnnotation("");
							bnCount--;
						}else if (i == 0){
							//No, generate a new name and put it into the lookup table
							current.setByIndex(pos, "_:g"+counter.getNewSym());
							current.setAnnotation("");
							bnCount--;
							lookupTable.put(bnName,counter.getCurrentValue());
						}
					}
					//Replace subject after object or end loop if subject has been replaced already
					if (pos == Triple.object){
						pos = Triple.subject;
					}else{
						break;
					}
				}

			}
		}

		//Sort triples again (with new deterministic blank node identifiers)
		Collections.sort(triples);	
	}
	
	/**
	 * Performs nondeterministic pre-canonicalization
	 * Use multiple one-step deterministic labeling passes
	 * 
	 * Steps (some may be skipped depending on blank nodes):
	 * 1) substituteBlankNodes & oneStepDeterministicLabelling
	 * 2) remove all triples with c14n:true predicate
	 * 3) substituteBlankNodes & oneStepDeterministicLabelling
	 * 4) Add new triples with c14n:true predicate for hard to label blank nodes
	 * 5) substituteBlankNodes & oneStepDeterministicLabelling
	 * 
	 * Comments "(Step A)" to "(Step F)" in code below refer to the algorithm description of Carroll
	 * 
	 * @param g  {@link NamedGraph} which will be canonicalized
	 * @throws Exception
	 */
	public void nondeterministicPreCanonicalization(NamedGraph g) throws Exception{
		//Get triples
		ArrayList<Triple> triples=g.getTriples();
		
		//Get C14N Predicate
		String c14n=Ontology.getC14NPredicate();
		
		//Count and substitute blank nodes
		substituteBlankNodes(triples);
		
		//Perform a one-step deterministic labeling (Step A)
		lookupTable = new HashMap<String,Integer>();
		counter=new GenSymCounter(bnCount);
		oneStepDeterministicLabelling(g);
		canonicalizeGraphNames(g);
		canonicalizeReifications(g);
		
		//Stop if there are no hard to label nodes (Step B)
		if ( bnCount==0 ){
			return;
		}
		
		//Delete triples with predicate "c14n:true" (Step C)
		for(Triple t:triples) {
			if (t.getPredicate().equals(c14n)){
				triples.remove(t);
			}
		}
		
		//Perform another one-step deterministic labeling (Step D)
		substituteBlankNodes(triples);		
		oneStepDeterministicLabelling(g);
		canonicalizeGraphNames(g);
		canonicalizeReifications(g);
		
		//Handle remaining hard to label nodes by adding new nodes (Step E)
		lookupTable.clear();
		counter.reset();
		ArrayList<Triple> newTriples = new ArrayList<Triple>();
		for(Triple t:triples) {
			//Object and subject replacement - two iterations in while loop:
			// 1) pos = Triple.object
			// 2) pos = Triple.subject
			int pos = Triple.object;
			while (true){
				if (t.getByIndex(pos).equals("~")){
					//Get original blank node identifier from annotation
					String bnName = t.getAnnotation();
					//Is blank node in lookup table?
					Integer lookupName = lookupTable.get(bnName);
					if (lookupName == null){
						//No, generate a new triple
						newTriples.add( new Triple(bnName, c14n, "\""+counter.getNewSym()+"\"") );
						lookupTable.put("x",counter.getCurrentValue());
					}
				}
				//Replace subject after object or end loop if subject has been replaced already
				if (pos == Triple.object){
					pos = Triple.subject;
				}else{
					break;
				}
			}
		}
		for (Triple addNew:newTriples){
			triples.add(addNew);
		}
		canonicalizeGraphNames(g);
		canonicalizeReifications(g);
		
		//Perform another one-step deterministic labeling (Step F)
		lookupTable.clear();
		counter.reset();
		substituteBlankNodes(triples);
		oneStepDeterministicLabelling(g);
		canonicalizeGraphNames(g);
		canonicalizeReifications(g);
		
		//Sort sub graphs
		Collections.sort(g.getChildren());
	}
	
	/**
	 * Adds c14n prefix to the graph collection (reduces output size)
	 * 
	 * @param gc  {@link GraphCollection} to which the C14N prefix will be added
	 */
	public void addC14NPrefix(GraphCollection gc){
		gc.addPrefix( new Prefix( Ontology.getC14NPrefix(), Ontology.getC14NURI() ) );
	}
	
	/**
	 * Canonicalizes graph names (handle blank nodes in graph names at same level) using the current lookup table
	 * 
	 * @param rootGraph  root graph whose subgraphs will be canonicalized
	 */
	private void canonicalizeGraphNames(NamedGraph rootGraph){
		//Iterate over all sub graphs
		for (NamedGraph g:rootGraph.getChildren()){
			//Only care about graphs with blank nodes
			if (g.getName().startsWith("_")){
				Integer lookupName = lookupTable.get(g.getName());
				if (lookupName!=null){
					g.setName("_:g"+counter.createSymStringFromInt(lookupName));
				}
			}
		}
	}
	
	/**
	 * Canonicalizes reification statements in an MSG using the current lookup table
	 * This function will only do something when reification statements are cached.
	 * This will only be the case when Tummarello2005 is used.
	 * Plain Carroll2003 does not use reifications.
	 * 
	 * @param g  named graph to deal with
	 */
	private void canonicalizeReifications(NamedGraph g){
		ArrayList<String[]> sigs=g.getMSGSignatures();
		if (sigs!=null && !sigs.isEmpty()){
			for (String[] sig:sigs){
				for (int i=0; i<=2; i+=2){
					if (sig[i].startsWith("_")){
						Integer lookupName = lookupTable.get(sig[i]);
						if (lookupName!=null){
							sig[i]="_:g"+counter.createSymStringFromInt(lookupName);
						}
					}
				}
			}
		}
	}
	
	public void postCanonicalize(GraphCollection gc){
		//Don't do anything
	}
	
	//######################################################## Hash
	/*
	 * Carrolls hashing method is defined at:
	 * RDF Graph Digest Techniques and Potential Applications
	 * http://www.hpl.hp.com/techreports/2004/HPL-2004-95.pdf
	 * 
	 * Graphs are combined with multiplication modulo n.
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
	 * Hashs graphs (recursive)
	 * 
	 * @param g  {@link NamedGraph} which is hashed
	 * @param d  used digest method for hashing
	 * @return  byte array with hash value
	 * @throws Exception
	 */
	private BigInteger hashGraph(NamedGraph g, MessageDigest d) throws Exception {		
		//Get hash base number
		BigInteger h=GraphBaseHasher.calculate(g,d);
		//Hash and combine triples
		h=hashTriples(h, g.getTriples(), d);
		//Hash and combine sub graphs
		for (NamedGraph subG:g.getChildren()){
			HashCombinator.combine( h, hashGraph(subG,d), HashCombinator.ca.Multiply );
		}
		return h;
		
	}
	
	/**
	 * Hash a vector of triples
	 * 
	 * @param hash  hash to start from as byte array
	 * @param triples  triples which will be hashed
	 * @param d  used digest method for hashing
	 * @return  resulting hash as byte array
	 * @throws Exception
	 */
	public BigInteger hashTriples(BigInteger hash, ArrayList<Triple> triples, MessageDigest d) throws Exception {
		//Sort triples
		Collections.sort(triples);
		
		//Hash triples
		d.reset();
		for (Triple t:triples){
			if (Ontology.isRelevantForHash(t)){
				byte[] tripleBytes=(t.getSubject()+t.getPredicate()+t.getObject()).getBytes();
				d.update(tripleBytes);
			}
		}
		BigInteger tripleHash=new BigInteger(d.digest());
		
		//Combine
		hash=HashCombinator.combine( hash, tripleHash, HashCombinator.ca.Multiply );
		
		return hash;
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
		return Ontology.getAlgorithmNameCarroll2003();
	}
		
}
