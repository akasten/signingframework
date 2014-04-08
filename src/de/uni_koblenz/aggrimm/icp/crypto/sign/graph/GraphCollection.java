package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;

/**
 * A graph collection (class 'GraphCollection') is a set of named graphs (Vector<NamedGraph>).
 * It may also contain a set of prefixes (Vector<Prefix>).
 * Prefixes can be resolved by calling 'resolvePrefixes()' and re-applied by calling 'applyPrefixes()'. 
 * 
 * There can be two special graph ('NamedGraph') types in a graph collection:
 * - name = "", depth = X:		unnamed/default graph for triples which are in graphs without a name, can be at any nesting depth
 * - name = "", depth = -1: 	virtual graph as container for all triples which are not in any graph at all ('root triples')
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class GraphCollection {
	private LinkedList<Prefix> prefixes;			//Prefixes
	private LinkedList<NamedGraph> graphs;			//Graphs in this graph collection
	private SignatureData signature;				//Signature data
	
	//######################################################## Constructors
	
	public GraphCollection() {
		this.prefixes = new LinkedList<Prefix>();
		this.graphs = new LinkedList<NamedGraph>();
	}
	
	//######################################################## Getters & Setters
	
	public LinkedList<Prefix> getPrefixes() {
		return prefixes;
	}

	public LinkedList<NamedGraph> getGraphs() {
		return graphs;
	}
	
	public void setGraphs(LinkedList<NamedGraph> graphs){
		this.graphs = graphs;
	}
	
	public SignatureData getSignature() {
		if (signature==null){
			signature=new SignatureData();
		}
		return signature;
	}

	public void setSignature(SignatureData signature) {
		this.signature = signature;
	}
	
	public boolean hasSignature(){
		return (signature!=null);
	}
	
	//######################################################## Helper functions
		
	/**
	 * Adds a prefix to the {@link GraphCollection}
	 * 
	 * @param p {@link Prefix} to add
	 */
	public void addPrefix(Prefix p){
		String pre=p.getPrefix();
		String iri=p.getIri();
		//Don't add if equal prefix already exists
		for (Prefix check:prefixes){
			if (check.getPrefix().equals(pre)){
				if (check.getIri().equals(iri)){
					return;
				}
			}
		}
		//Add
		prefixes.add(p);
	}
	
	/**
	 * Adds a graph to the {@link GraphCollection}
	 * 
	 * @param g {@link NamedGraph} to add
	 */
	public void addGraph(NamedGraph g){
		graphs.add(g);
	}
	
	/** Check if the {@link GraphCollection} has any triples
	 * 
	 * @return true if there are any triples, false otherwise
	 */
	public boolean hasTriples(){
		for (NamedGraph subG:graphs){
			if (subG.tripleCount(true)>0){
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Gets the triple count of the {@link GraphCollection}
	 * 
	 * @return number of triples in the {@link GraphCollection}
	 */
	public int tripleCount(){
		int count=0;
		for (NamedGraph subG:graphs){
			count+=subG.tripleCount(true);
		}
		return count;
	}
	
	/**
	 * Get all triples at the root level (outside any graph) of the {@link GraphCollection}
	 * 
	 * @return vector of triples at root level
	 */
	public ArrayList<Triple> getRootTriples(){
		for (NamedGraph g:graphs){
			if ((g.getDepth()==-1)&&(g.getName().length()==0)){
				return g.getTriples();
			}
		}
		return new ArrayList<Triple>();
	}
	
	/**
	 * Gets the blank node count of the {@link GraphCollection}
	 * 
	 * @param recursive		count recursively in all sub graphs?
	 * @param distinct		count distinct blank nodes only?
	 * @return				blank node count
	 * 
	 * @deprecated
	 */
	@Deprecated
	public int blankNodeCount(boolean recursive, boolean distinct){
		int count=0;
		for (NamedGraph subG:graphs){
			count+=subG.blankNodeCount(recursive,distinct);
		}
		return count;
	}
	
	/**
	 * Gets statistics of the {@link GraphCollection}
	 * Array index - value
	 * 0 - total triple count
	 * 1 - IRIs / resources
	 * 2 - literals
	 * 3 - blank nodes
	 * 4 - distinct blank nodes
	 * 5 - Unique subject URIs
	 * 
	 * @return array with statistics
	 */
	public int[] getStats(){
		int[] stats=new int[6];
		for (NamedGraph subG:graphs){
			int[] r=subG.getStats(true);
			for (int i=0; i<stats.length; i++){
				stats[i]+=r[i];
			}
		}
		return stats;
	}
	
	/**
	 * Counts triples with specified predicate in the {@link GraphCollection}
	 * 
	 * @param predicate URI of the predicate
	 * @return number of occurrences
	 */
	public int countPredicate(String predicate){
		int count=0;
		for (NamedGraph subG:graphs){
			count+=subG.countPredicate(predicate);
		}
		return count;
	}
	
	/**
	 * Counts duplicate triples in the {@link GraphCollection}
	 * Attentions: Only cares about triples (MSGs are ignored) and sorts all triples!
	 * 
	 * @return number of duplicates
	 */
	public int countDuplicates(){
		int count=0;
		for (NamedGraph subG:graphs){
			count+=subG.countDuplicates();
		}
		return count;
	}
	
	/**
	 * Resolves all prefixes of the {@link GraphCollection}
	 */
	public void resolvePrefixes(){
		//Sub graphs
		for (NamedGraph subG:graphs){
			subG.resolvePrefixes(prefixes);
		}
	}
	
	/**
	 * Applies all prefixes of the {@link GraphCollection}
	 */
	public void applyPrefixes(){
		//Sub graphs
		for (NamedGraph subG:graphs){
			subG.applyPrefixes(prefixes);
		}
	}
	
	/**
	 * Sorts all graphs in the {@link GraphCollection}
	 */
	public void sortGraphs(){
		Collections.sort(graphs);
		//Sub graphs
		for (NamedGraph subG:graphs){
			subG.sortGraphs();
		}
	}
		
	/**
	 * Checks if {@link GraphCollection} has been hashed
	 * 
	 * @return true if it has been hashed, false otherwise
	 */
	public boolean isHashed(){
		if (signature!=null){
			if (signature.getGraphDigestMethod().length()>0){
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Checks if there are any MSGs in the {@link GraphCollection}
	 * @return true if there are MSGs, false otherwise
	 */
	public boolean isUsingMSGs(){
		for (NamedGraph g:graphs){
			if (g.isUsingMSGs()){
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Checks if the graph collection and all it's content is well-formed
	 * 
	 * @return  true if its well-formed
	 * @throws Exception  if its malformed
	 */
	public boolean isValid() throws Exception {
		int virtualGraphs=0;
		int defaultGraphs=0;
		for (NamedGraph g:graphs){
			if (g.getDepth()==-1){
				virtualGraphs++;
				if (virtualGraphs>1){
					throw new Exception("Multiple virtual graphs");
				}
			}
			if (g.getName().length()==0){
				defaultGraphs++;
				if (defaultGraphs>1){
					throw new Exception("Multiple default/nameless graphs");
				}
			}
			if (!g.isValid()){
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Clears the graph collection by removing all contained graphs
	 */
	public void clear(){
		for (NamedGraph g:graphs){
			g.clear();
		}
	}
	
	/**
	 * Updates the depths of all contained graphs
	 */
	public void updateDepths(){
		for (NamedGraph g:graphs){
			g.updateDepths(0,null);
		}
	}
	
	//######################################################## Java Functions
	
	/**
	 * Converts the {@link GraphCollection} to a string (used for printing and debugging)
	 * Attention: May not work properly with very big graphs
	 * 
	 * @return			string representation
	 */
	public String toString() {
		String result="";
		
		//Prefixes
		for (Prefix p:this.prefixes){
			result+=(p);
		}
				
		//Graphs
		for (NamedGraph subG:graphs){
			result+=subG.toString();
		}
		
		return result;
	}
	
	
}
