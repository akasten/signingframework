package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

import java.math.BigInteger;

/**
 * Class used by Fisteus2010 only to save variable (blank node) hashes
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class NodeHash implements Comparable<NodeHash> {
	private String var;				//Variable / Blank Node
	private BigInteger hash;		//Hash value
	
	//######################################################## Constructors
	
	public NodeHash(String var, BigInteger hash){
		this.var=var;
		this.hash=hash;
	}
	
	//######################################################## Getters & Setters
	
	public String getVar(){
		return var;
	}
	
	public BigInteger getHash(){
		return hash;
	}
	
	public void setHash(BigInteger hash){
		this.hash=hash;
	}
	
	//######################################################## Java Functions
	
	public int compareTo(NodeHash vh) {
		return this.hash.compareTo(vh.getHash());
	}
	
}
