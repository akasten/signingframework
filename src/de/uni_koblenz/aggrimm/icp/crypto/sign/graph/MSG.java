package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

import java.math.BigInteger;
import java.util.ArrayList;

/**
 * MSG = Minimum self-contained graph
 * A MSG consists of a set of N triples with N>=1 (there should not be any empty MSGs).
 * These triples have in common that they contain the same blank nodes (in subject and/or object position).
 * A MSG can consist of just one triple in case it has no blank nodes or in case it has blank nodes which are not part of any other triple.
 * A set of triples can be split into a set of MSGs using the method NamedGraph.SplitIntoMSGs().
 * MSGs can have a hash, signature and certificate.
 * MSGs are currently only used by the algorithm of Tummarello. All other algorithms do not split sets of triples into MSGs.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class MSG {
	private ArrayList<Triple> triples;						//Triples belonging to this MSG
	private BigInteger hash;								//Hash
	private String signature;								//Signature
	private String certificate;								//Certificate
	
	//######################################################## Constructors
	
	public MSG() {
		this.triples = new ArrayList<Triple>();
	}
	
	/**
	 * Create new MSG with one triple in it
	 * 
	 * @param t  triple which will be in the MSG
	 */
	public MSG(Triple t){
		this.triples = new ArrayList<Triple>(1);
		this.triples.add(t);
	}
	
	/**
	 * Create new MSG with a vector of triples in it
	 * 
	 * @param triples  vector of triples which will be in the MSG
	 */
	public MSG(ArrayList<Triple> triples){
		this.triples = triples;
	}
	
	
	//######################################################## Getters & Setters

	public ArrayList<Triple> getTriples() {
		return triples;
	}

	public void setTriples(ArrayList<Triple> triples) {
		this.triples = triples;
	}
	
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
	
	public String getCertificate() {
		return certificate;
	}
	
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	
	//######################################################## Helper functions
	
	/**
	 * Adds a triple to this MSG
	 * 
	 * @param t triple to add
	 */
	public void addTriple(Triple t){
		triples.add(t);
	}
	
	/**
	 * Adds a list of triples to this MSG
	 * 
	 * @param list  list of triples to add
	 */
	public void addTriples(ArrayList<Triple> list){
		triples.addAll(list);
	}
	
	/**
	 * Checks if MSG contains a certain triple (specified by String array with size 3)
	 * 
	 * @param triple	triple as string array
	 * @return			true if MSG contains this triple, false otherwise
	 */
	public boolean containsTriple(String[] triple){
		for (Triple t:triples){
			if (t.isSPOequal(triple)){
				return true;
			}
		}
		return false;
	}
	
	
	//######################################################## Java Functions
	
	/**
	 * Converts MSG to a string (used for printing and debugging)
	 * 
	 * @return			string representation
	 */
	public String toString() {
		String result="";
		for (Triple t:triples){
			result+=(t+"\n");
		}
		return result;
	}
	
	/**
	 * Checks if this MSG is equal to another MSG
	 * 
	 * @param o {@link MSG} to compare with
	 * @return  true if equal, false otherwise
	 */
	public boolean equals(Object o){
		if (o==null){
			return false;
		} else if (this==o){
			return true;
		} else if (this.getClass() != o.getClass()){
			return false;
		} else {
			return this.getTriples().equals( ((MSG)o).getTriples() );
		}
	}
	
}
