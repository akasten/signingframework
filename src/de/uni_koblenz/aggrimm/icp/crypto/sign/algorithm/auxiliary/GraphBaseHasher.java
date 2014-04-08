package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary;

import java.math.BigInteger;

import java.security.MessageDigest;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.NamedGraph;

/**
 * Calculate base hash which for a graph which is combined with the hashes of triples
 *
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class GraphBaseHasher {
	
	/**
	 * Calculates the base hash of a graph as BigInteger
	 * 
	 * @param g	Graph
	 * @param d	Digest method
	 * @return base hash as BigInteger
	 * @throws Exception
	 */
	public static BigInteger calculate(NamedGraph g, MessageDigest d) throws Exception {
		String name=g.getName();
		if (g.getDepth()==-1){
			//Virtual Graph (base hash for root triples)
			return BigInteger.ONE;
		} else if (name.length()==0){
			//Unnamed graph
			//Take triple count as base number (+2 to be always different from virtual graph)
			int tripleCount=g.tripleCount(false)+2;
			return BigInteger.valueOf(tripleCount);
		} else {
			//Named Graph
			return new BigInteger(d.digest(name.getBytes("UTF8"))); 
		}
	}
	
}
