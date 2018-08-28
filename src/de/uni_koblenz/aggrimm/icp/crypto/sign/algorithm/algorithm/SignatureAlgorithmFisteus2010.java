package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.algorithm;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.SignatureAlgorithmInterface;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.GraphBaseHasher;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary.HashCombinator;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic.Assembler;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic.Signer;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic.Verifier;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.GraphCollection;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.NamedGraph;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.NodeHash;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.SignatureData;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.Triple;
import de.uni_koblenz.aggrimm.icp.crypto.sign.ontology.Ontology;

/**
 * Signature Algorithm "Fisteus2010"
 * Ontology Name: fisteus-2010
 * 
 * Based on: Fisteus, J.A., Carc�a, N.F., Fern�ndez, L.S., Kloos, C.D.: Hashing and canonicalizing Notation 3 graphs. JCSS 76 (2010), 663-685
 * Comments in the code below naming a section/table/equation refer to that source.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureAlgorithmFisteus2010 implements SignatureAlgorithmInterface {
	/**
	 * Modulo number (2^64 - 59, largest unsigned 64 bit prime, Section 5.2)
	 */
	private static final BigInteger N_XOR = HashCombinator.N_XOR;
	private static final BigInteger N_MUL = HashCombinator.N_MUL;
	
	/**
	 * Message digest (cached for quick access)
	 */
	private MessageDigest digestGen;
	
	/**
	 * Collisions
	 */
	private int collisions;
		
	/** 
	 * Hashing Constants (Section 5.4)
	 * Values as specified in Section 9.1, Table 1
	 * Not all values are used because this implementation has been simplified as it does not use the N3 format
	 *
	 *------------------------------------------------------------------------------------------------------------
	 *								Identifier	Value				  							Description
	 *------------------------------------------------------------------------------------------------------------
	 */
	static private final BigInteger kSubj=		new BigInteger("4754645121639434670");			//Subject
	static private final BigInteger kPred=		new BigInteger("52591467729844340");			//Predicate
	static private final BigInteger kObj=		new BigInteger("6279390922760334309"); 			//Object
	static private final BigInteger kDType=		new BigInteger("13394959525758901351");			//Data Type (for literal, denoted with: ^^)
	static private final BigInteger kLang=		new BigInteger("8277611958972876912");			//Language (for literal, denoted with: @)
	static private final BigInteger kExist=		new BigInteger("14159263174629805858");			//existentially-quantified variable (or: blank node)
	static private final BigInteger kLab=		new BigInteger("4719830516364819251");			//Label
	static private final BigInteger kLit=		new BigInteger("8565450179243949149");			//Literal
		
	//######################################################## Canonicalize
	
	public void canonicalize(GraphCollection gc) throws Exception {	
		canonicalize(gc,"sha-256");
	}
	
	/**
	 * Canonicalization sorts all triples by their hash values
	 * This means that triples have to be hashed first 
	 * 
	 * @param gc
	 * @param digestAlgo
	 * @throws Exception
	 */
	public void canonicalize(GraphCollection gc, String digestAlgo) throws Exception {

		//Get Signature
		SignatureData sig=gc.getSignature();
		
		//Prepare Digest
		digestGen=MessageDigest.getInstance(digestAlgo);
		sig.setDigestGen(digestGen);
		
		//Prepare Graphs (prepare a hash map for blank nodes in each graph)
		for (NamedGraph g:gc.getGraphs()){
			hashGraphPrepare(g);
		}
		
		//Run canonicalization steps until no collisions occur
		for (int i=0; i<10; i++){
			int previousCollisions=collisions;
			collisions=0;
			
			//Hash statements in all graphs and subgraphs
			//Use initial value for blank nodes (kExist) if there are no calculated hashes for them yet
			//Save hashes for triples in triples
			for (NamedGraph g:gc.getGraphs()){
				hashGraph(g);
			}
			
			//Hash variables (blank nodes)
			for (NamedGraph g:gc.getGraphs()){
				computeHashVars(g);
			}

			//Count Collisions
			for (NamedGraph g:gc.getGraphs()){
				hashGraphCountCollisions(g);
			}
			
			//System.out.println("******* ITERATIONS: " + i);
			
			//End if there are no collisions
			if (collisions==0){
				break;
			//End if didn't manage to reduce number of collisions
			}else if (i>0 && collisions>=previousCollisions){
				break;
			}
			if (i==9){
				throw new Exception("Failed to hash graph collection. Unresolved collisions after 10 iterations.");
			}
		}

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
	 * @throws Exception
	 */
	private void canonicalizeGraph(NamedGraph g) throws Exception{
		
		//Rename Blank Nodes
		int i=1;
		if (g.getVariableHashes()!=null){
			Collections.sort(g.getVariableHashes());
			for (NodeHash nh:g.getVariableHashes()){
				String blankNode=nh.getVar();
				//System.out.println("bn: "+blankNode+" "+nh.getHash());
				for (Triple t:g.getTriples()){
					for (int j=0; j<=2; j+=2){
						//Blank node detected!
						if (t.getByIndex(j).equals(blankNode)){
							//Replace blank node with new blank node identifier
							t.setByIndex(j,"_:bn"+i);
						}
					}
				}
				i++;
			}
		}
		
		//Rename sub graphs
		for (NamedGraph subG:g.getChildren()){
			if (subG.getName().startsWith("_")){
				i=1;
				if (g.getVariableHashes()!=null){
					for (NodeHash nh:g.getVariableHashes()){
						if (subG.getName().equals(nh.getVar())){
							subG.setName("_:bn"+i);
						}
						i++;
					}
				}
			}
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
	
	public void hash(GraphCollection gc, String digestAlgo) throws Exception {
		
		//Get Signature
		SignatureData sig=gc.getSignature();
		
		//Prepare Digest
		digestGen=MessageDigest.getInstance(digestAlgo);
		sig.setDigestGen(digestGen);
		
		//Prepare Graphs (prepare a hash map for blank nodes in each graph)
		for (NamedGraph g:gc.getGraphs()){
			hashGraphPrepare(g);
		}
		
		//Run canonicalization steps until no collisions occur
		BigInteger h=BigInteger.ONE;

		//Hash statements in all graphs and subgraphs
		//Use initial value for blank nodes (kExist) if there are no calculated hashes for them yet
		//Save hashes for triples in triples
		//Hash variables (blank nodes)
		//Combine Variables and Statements
		for (NamedGraph g:gc.getGraphs()){
			hashGraph(g);
			computeHashVars(g);
			h = HashCombinator.combine( h, combineVarsAndStatements(g), HashCombinator.ca.Multiply );
		}

		//Update Signature Data
		sig.setGraphDigestMethod( Ontology.getDigestPrefix()+getName() );
		sig.setHash(h);
	}
	
	/**
	 * Prepare graphs for hashing (recursive)
	 * 
	 * @param g  graph to prepare
	 */
	private void hashGraphPrepare(NamedGraph g){
		//Prepare variable list for this graph
		g.setVariableHashes(new ArrayList<NodeHash>());
		
		//Prepare sub graphs
		for (NamedGraph subG:g.getChildren()){
			hashGraphPrepare(subG);
		}
	}
	
	/**
	 * Hash graphs (recursive)
	 * 
	 * @param g
	 * @throws Exception  if graph contains unknown resource types
	 */
	private void hashGraph(NamedGraph g) throws Exception {
		//Hash triples (resulting hash values are saved directly in triples)
		for (Triple t:g.getTriples()){
			hashTriple(t,g);
		}
		
		//Hash sub graphs
		for (NamedGraph subG:g.getChildren()){
			hashGraph(subG);
		}
	}
	
	/**
	 * Count Collisions (recursive)
	 * 
	 * @param g
	 */
	private void hashGraphCountCollisions(NamedGraph g){
		//Sort triples in graph by their hash values
		Collections.sort(g.getTriples(), new Comparator<Triple>() {
			public int compare(Triple t1, Triple t2) {
				if (t1.getHash()==null){
					throw new RuntimeException("hash of triple "+t1+" does not exist");
				}
				if (t2.getHash()==null){
					throw new RuntimeException("hash of triple "+t2+" does not exist");
				}				
				return t2.getHash().compareTo(t1.getHash());
			}
		});
		
		//Count hash collisions in statements
		BigInteger prevHash=null;
		for (Triple t:g.getTriples()){
			BigInteger curHash=t.getHash();
			if (curHash.equals(prevHash)){
				collisions++;
			}
			prevHash=curHash;
		}
		
		//Sort variable hashes by their hash values
		Collections.sort(g.getVariableHashes());
		
		//Count hash collisions in variables
		prevHash=null;
		for (NodeHash nh:g.getVariableHashes()){
			BigInteger curHash=nh.getHash();
			if (curHash.equals(prevHash)){
				collisions++;
			}
			prevHash=curHash;
		}
		
		//Count collisions in sub graphs
		for (NamedGraph subG:g.getChildren()){
			hashGraphCountCollisions(subG);
		}
	}
	
	/**
	 * Calculate hash for a triple (statement)
	 * Described in section "5.6. Hashing Statements" (equation 6)
	 * Resulting hash is saved directly in triple
	 * 
	 * @param t
	 * @param g
	 * @throws Exception  if triple contains unknown resource types
	 */
	private void hashTriple(Triple t, NamedGraph g) throws Exception {
		if (Ontology.isRelevantForHash(t)){
			t.setHash (
						hashResource(t.getSubject(),g).multiply(kSubj).mod(N_XOR).xor(			//Subject
						hashResource(t.getPredicate(),g).multiply(kPred).mod(N_XOR)).xor(		//Predicate
						hashResource(t.getObject(),g).multiply(kObj).mod(N_XOR)					//Object
						).mod(N_XOR)
					);
		}else{
			t.setHash(BigInteger.ONE);
		}
	}
	
	/**
	 * Calculate hash for an RDF resource (provided as string)
	 * 
	 * @param r  RDF resource string to hash
	 * @param g  {@link NamedGraph} containing the resource
	 * @return  hash value as BigInteger
	 * @throws Exception  if resource type of r is unknown
	 */
	private BigInteger hashResource(String r, NamedGraph g) throws Exception{
		BigInteger h=BigInteger.ONE;
		//Get Resource Type
		if (r.length()>0){
			char first=r.charAt(0);
			switch (first){
			
				//######################### Label / URI / Predicate
				//Described in section "5.7. Hashing labeled nodes and predicates" (equation 7)
				case '<':
					//Use string hashing function, exclude < and > when hashing
					return hashString(r.substring(1,r.length()-1)).xor(kLab).mod(N_XOR);
					
				//######################### Literal
				//Described in section "5.8. Hashing literal values" (equations 8,9,10)
				case '"':
					//Set default hash values for literal parts
					BigInteger hLan=BigInteger.ONE;
					BigInteger hDType=BigInteger.ONE;
					BigInteger hText=BigInteger.ONE;
					//Extract Language / Data Type
					//Note: The official EBNF actually does not allow language AND data type in the same literal (mutually exclusive)
					//This code is able to handle literals with language OR/AND data type in all orders anyway.
					if (r.endsWith("\"")){
						//Ends with quote - this means there is just the plain literal without Language / Data Type
						hText=hashString(r.substring(1,r.length()-1));						
					}else{
						//Does not end with quote - find the ending quote in the string
						int len=r.length();
						int i;
						for (i=1; i<len; i++){
							if (r.charAt(i)=='"'){
								break;
							}
						}
						hText=hashString(r.substring(1,i));
						//Is the string long enough to contain additional information?
						if ((i+2)<len){
							if (r.charAt(i+1)=='@'){
								//Language								
								if (r.contains("^^")){
									//Language + Datatype
									String parts[]=r.substring(i+2).split("\\^\\^");
									if (parts.length>=2){
										hLan=hashString(parts[0]).xor(kLang).mod(N_XOR);
										hDType=hashString(parts[1]).xor(kDType).mod(N_XOR);
									}
								}else{
									//Language only
									hLan=hashString(r.substring(i+2)).xor(kLang).mod(N_XOR);							
								}
							}else if (r.charAt(i+1)=='^'){
								//Data Type
								if (r.charAt(i+2)=='^'){
									if (r.contains("@")){
										//Data Type + Language
										String parts[]=r.substring(i+3).split("@");
										if (parts.length>=2){
											hDType=hashString(parts[0]).xor(kDType).mod(N_XOR);
											hLan=hashString(parts[1]).xor(kLang).mod(N_XOR);											
										}
									}else{
										//Data Type only
										hDType=hashString(r.substring(i+3)).xor(kDType).mod(N_XOR);										
									}
								}
							}
						}
					}
					//Calculate Hash
					return ( hText.multiply(hLan).multiply(hDType).mod(N_XOR).xor(kLit).mod(N_XOR) );
					
				//######################### Blank Node
				//Described in section "5.5. Hashing a formula" (equation 4)
				case '_':
					//Get Hash
					ArrayList<NodeHash> vars=g.getVariableHashes();
					for (NodeHash nh:vars){
						if (nh.getVar().equals(r)){
							return nh.getHash();
						}
					}
					//Not found, use kExist
					g.getVariableHashes().add(new NodeHash(r, kExist));
					return ( kExist );
									
				//######################### Lists
				//Described in section "5.9. Hashing lists" (equations 11,12,13)
					//no n3 -> no special list treatment
					
				//######################### Sets
				//Described in section "5.10. Hashing sets" (equation 14)
					//no n3 -> no special set treatment
					
				//######################### Other values
				default:
					throw new Exception("Unexpected node value / resource type '"+r+"'");
			}	
		}
		return h;
	}
	
	/**
	 * Hash String 
	 * Described in section "5.3. Hashing string values"
	 * "any good text-hashing algorithm may be chosen"
	 * 
	 * @param s  string to hash
	 * @return  hash value as BigInteger
	 */
	private BigInteger hashString(String s){
		return new BigInteger( digestGen.digest(s.getBytes(StandardCharsets.UTF_8)) );
	}
	
	/**
	 * Algorithm 1: compute_hash_vars
	 * Described in section "5.11.2. Computing the hash of variables"
	 * 
	 * @param g  {@link NamedGraph} to process
	 */
	private void computeHashVars(NamedGraph g){
		//h local{f}(v) is always kExist (there are blank nodes only and no other variable types because no N3)
		//Statements
		for (Triple t:g.getTriples()){
			if (Ontology.isRelevantForHash(t)){
				processTerm(t.getSubject(),t.getHash(),kSubj,g);
				processTerm(t.getObject(),t.getHash(),kObj,g);
			}
		}
		//Hash variables in sub graphs
		for (NamedGraph subG:g.getChildren()){
			computeHashVars(subG);
		}
	}
	
	/**
	 * Algorithm 2: process_term
	 * Described in section "5.11.2. Computing the hash of variables"
	 * 
	 * @param term  term to hash
	 * @param hash  initial hash value as BigInteger
	 * @param path  path of term
	 * @param g  {@link NamedGraph} containing the term
	 */
	private void processTerm(String term, BigInteger hash, BigInteger path, NamedGraph g){
		
		//Is term a variable (blank node)?
		if (term.startsWith("_")){
			//Yes, it's a blank node! Try to get the hash
			ArrayList<NodeHash> vars=g.getVariableHashes();
			NodeHash currentNH=null;
			for (NodeHash nh:vars){
				if (nh.getVar().equals(term)){
					currentNH=nh;
					break;
				}
			}
			if (currentNH==null){
				//Hash does not exist yet - set to kExist (this is done in Algorithm 1 in the original implementation)
				currentNH=new NodeHash(term,kExist);
				vars.add(currentNH);
			}
			//Update hash
			//Calculation taken from part "if v declared at f or any upper formula then"
			currentNH.setHash(currentNH.getHash().multiply( hash.xor(path).mod(N_XOR) ).mod(N_MUL));
			
		}
		//All other cases (list, set, formula) are not handled because this implementation does not use N3
	}
	
	/**
	 * Combine variables and statements (recursive)
	 * Described in section "5.5. Hashing a formula" (equation 5)
	 * 
	 * @param g  {@NamedGraph} to handle
	 * @return  hash value as BigInteger
	 * @throws Exception  if fails to generate base hash
	 */
	private BigInteger combineVarsAndStatements(NamedGraph g) throws Exception {
		//Calculate hash from statement hashes and variable hashes
		BigInteger h=GraphBaseHasher.calculate(g, digestGen);
		
		//Statements/Triples
		for (Triple t:g.getTriples()){
			if (Ontology.isRelevantForHash(t)){
				h = HashCombinator.combine( h, t.getHash(), HashCombinator.ca.Multiply );
			}
		}
		
		//Variables
		for (NodeHash nh:g.getVariableHashes()) {
			h = HashCombinator.combine( h, nh.getHash(), HashCombinator.ca.Multiply );
		}
		
		//Combine variables in sub graphs
		for (NamedGraph subG:g.getChildren()){
			h = HashCombinator.combine( h, combineVarsAndStatements(subG), HashCombinator.ca.Multiply );
		}
		
		//Return
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
		return Ontology.getAlgorithmNameFisteus2010();
	}
	
}
