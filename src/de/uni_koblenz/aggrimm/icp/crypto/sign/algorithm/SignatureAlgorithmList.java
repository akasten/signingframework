package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm;

import java.util.LinkedList;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.algorithm.*;

/**
 * A list containing all available signature algorithms.
 * Required for automatic signature verification.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class SignatureAlgorithmList {
	private static LinkedList<SignatureAlgorithmInterface> list;
	
	//######################################################## Getters
	
	/**
	 * Get algorithm list (initialize first if necessary)
	 * @return list of signature algorithms
	 */
	public static LinkedList<SignatureAlgorithmInterface> getList() {
		initialize();
		return list;
	}
	
	/**
	 * Get algorithm from list by name
	 * 
	 * @param name			name of signature algorithm
	 * @return				signature algorithm instance
	 * @throws Exception	if algorithm with specified name has not been found
	 */
	public static SignatureAlgorithmInterface getAlgorithm(String name) throws Exception {
		initialize();
		for (SignatureAlgorithmInterface a:list){
			if (a.getName().equals(name)){
				return a;
			}
		}
		throw new Exception("Signature algorithm '"+name+"' does not exist");
	}
	
	
	//######################################################## Functions
	
	/**
	 * Initializes an algorithm list
	 * Algorithms which are added to this framework should be added to this list as well.
	 * Algorithms in this list will be used for automated verification and evaluation.
	 */
	private static void initialize(){
		//Initialization has to be done only once
		if (list==null){
			//Prepare list
			list = new LinkedList<SignatureAlgorithmInterface>();
			//Add algorithms to list
			list.add(new SignatureAlgorithmCarroll2003());
			list.add(new SignatureAlgorithmFisteus2010());
			list.add(new SignatureAlgorithmSayers2004());
			list.add(new SignatureAlgorithmTummarello2005());
		}
	}
	
}
