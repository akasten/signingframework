package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;

/**
 * A named graph is a graph with an IRI as identifier.
 * The graph content is defined by a set of triples (ArrayList<Triple>) and sub graphs (ArrayList<NamedGraph>).
 * It can also contain triples in MSGs instead of a direct ArrayList of triples.
 * Each graph has a nesting depth and nested graphs have a parent graph.
 * Named graphs are commonly stored in graph collections (see class 'GraphCollection').
 * 
 * Besides 'normal' named graphs there are two special types (see comment in class {@link GraphCollection}).
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class NamedGraph implements Comparable<NamedGraph> {
	private String name;										//Name (IRI) identifying this graph, empty for default graph
	private ArrayList<Triple> triples;							//Triples belonging to this graph
	private LinkedList<NamedGraph> children;					//Children of this graph
	private ArrayList<MSG> msgs;								//Minimum self-contained graphs in this graph (can be null if there are no MSGs)
	private NamedGraph parent;									//Parent Graph (or null if this is a root graph without parents)
	private int depth;											//Nesting depth in graph hierarchy (starting with 0 for root graphs without parents, -1 for root graph with triples outside any graph)
	
	private ArrayList<NodeHash> variableHashes;					//Variable Hashes (used by Fisteus 2010 algorithm)
	private ArrayList<String[]> msgSignatures;					//MSG Signatures (used by Tummarello 2005 algorithm)

	//######################################################## Constructors
	
	public NamedGraph(String name, int depth, NamedGraph parent) {
		this.name = name;
		this.depth = depth;
		this.triples = new ArrayList<Triple>();
		this.children = new LinkedList<NamedGraph>();
		this.parent = parent;
		//Add to ArrayList
		if (parent!=null){
			//Add to children
			parent.children.add(this);
		}
	}

	
	//######################################################## Getters & Setters
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	public int getDepth() {
		return depth;
	}

	public ArrayList<Triple> getTriples() {
		return triples;
	}

	public LinkedList<NamedGraph> getChildren() {
		return children;
	}
	
	public void setChildren(LinkedList<NamedGraph> children) {
		this.children = children;
	}
	
	public NamedGraph getParent() {
		return parent;
	}
	
	public ArrayList<NodeHash> getVariableHashes() {
		return variableHashes;
	}

	public void setVariableHashes(ArrayList<NodeHash> variableHashes) {
		this.variableHashes = variableHashes;
	}
	
	public ArrayList<MSG> getMSGs() {
		return msgs;
	}
	
	public ArrayList<String[]> getMSGSignatures(){
		return msgSignatures;
	}
	
	//######################################################## Helper functions
	
	/**
	 * Gets triple count (can be recursive to include all sub graphs)
	 * 
	 * @param recursive		count recursively in all sub graphs?
	 * @return				triple count
	 */
	public int tripleCount(boolean recursive){
		int count=triples.size();
		if (msgs!=null){
			for (MSG msg:msgs){
				count+=msg.getTriples().size();
			}
		}
		//Count for sub graphs
		if (recursive){
			for (NamedGraph subG:this.children){
				count+=subG.tripleCount(true);
			}
		}
		//Return result
		return count;
	}
	
	/**
	 * Gets blank node count
	 * 
	 * @param recursive		count recursively in all sub graphs?
	 * @param distinct		count distinct blank nodes only?
	 * @return				blank node count
	 * 
	 * @deprecated
	 */
	@Deprecated
	public int blankNodeCount(boolean recursive, boolean distinct){
		//Count in triples
		int count=0;
		ArrayList<String> list=new ArrayList<String>();
		for (Triple t:triples){
			//Subject
			if (t.getSubject().startsWith("_:")){
				if (distinct){
					if (!list.contains(t.getSubject())){
						list.add(t.getSubject());
						count++;
					}
				}else{
					count++;
				}
			}
			//Object
			if (t.getObject().startsWith("_:")){
				if (distinct){
					if (!list.contains(t.getObject())){
						list.add(t.getObject());
						count++;
					}
				}else{
					count++;
				}
			}
		}
		//Count in MSGs
		if (msgs!=null){
			for (MSG msg:msgs){
				for (Triple t:msg.getTriples()){
					//Subject
					if (t.getSubject().startsWith("_:")){
						if (distinct){
							if (!list.contains(t.getSubject())){
								list.add(t.getSubject());
								count++;
							}
						}else{
							count++;
						}
					}
					//Object
					if (t.getObject().startsWith("_:")){
						if (distinct){
							if (!list.contains(t.getObject())){
								list.add(t.getObject());
								count++;
							}
						}else{
							count++;
						}
					}
				}
			}
		}
		//Count for sub graphs
		if (recursive){
			for (NamedGraph subG:this.children){
				count+=subG.blankNodeCount(recursive,distinct);
			}
		}
		//Return result
		return count;
	}
	
	/** Gets statistics of a named graph (can be recursive to include sub graphs if recursive is set to true)
	 * Array index - value
	 * 0 - total triple count
	 * 1 - IRIs / resources
	 * 2 - literals
	 * 3 - blank nodes
	 * 4 - distinct blank nodes
	 * 5 - Unique subject URIs
	 * 
	 * @param recursive count recursively in all sub graphs?
	 * @return array with statistics
	 */
	public int[] getStats(boolean recursive){
		int[] stats=new int[6];
		HashSet<String> blankNodes=new HashSet<String>();
		HashSet<String> USUs=new HashSet<String>();
		//Triples
		if (!triples.isEmpty()){
			int[] r=getStatsTripleList(triples,blankNodes,USUs);
			for (int i=0; i<stats.length; i++){
				stats[i]+=r[i];
			}
		//MSGs
		}else if(msgs!=null){
			for (MSG msg:msgs){
				int[] r=getStatsTripleList(msg.getTriples(),blankNodes,USUs);
				for (int i=0; i<stats.length; i++){
					stats[i]+=r[i];
				}
			}
		}
		//Sub Graphs
		if (recursive){
			for (NamedGraph subG:children){
				int[] r=subG.getStats(recursive);
				for (int i=0; i<stats.length; i++){
					stats[i]+=r[i];
				}
			}
		}
		
		return stats;
	}
	
	/** Get statistics of a triple list
	 * Array index - value
	 * 0 - total triple count
	 * 1 - IRIs / resources
	 * 2 - literals
	 * 3 - blank nodes
	 * 4 - distinct blank nodes
	 * 5 - Unique subject URIs
	 * 
	 * @param triples  triples to get stats from
	 * @param blankNodes  list of detected blank nodes
	 * @param USUs  list of detected USUs (unique subject URIs)
	 * @return array with statistics
	 */
	public static int[] getStatsTripleList(ArrayList<Triple> triples,
			HashSet<String> blankNodes, HashSet<String> USUs){
		int[] stats=new int[6];
		stats[0]+=triples.size();
		//Iterate over all triples
		for (Triple t:triples){
			//Check subject, predicate and object
			for (int i=0; i<3; i++){
				String resource=t.getByIndex(i);
				char first=resource.charAt(0);
				switch (first){
					//IRI
					case '<':
						stats[1]++;
						//Unique Subject URIs
						if (i==0){
							if (!USUs.contains(resource)){
								USUs.add(resource);
								stats[5]++;
							}
						}
						break;
					//Literal
					case '"':
						stats[2]++;
						break;
					//Blank Node
					case '_':
						stats[3]++;
						//Distinct?
						if (!blankNodes.contains(resource)){
							blankNodes.add(resource);
							stats[4]++;
						}
						break;
					//Others - assume that it is a IRI (prefixed IRI or 'a')
					default:
						stats[1]++;
				}
			}
		}
		return stats;
	}

	/**
	 * Counts triples with specified predicate
	 * 
	 * @param predicate URI of the predicate
	 * @return number of occurrences
	 */
	public int countPredicate(String predicate){
		int count=0;
		//Triples
		for (Triple t:triples){
			if (t.getPredicate().equals(predicate)){
				count++;
			}
		}
		//Triples in MSGs
		if (msgs!=null){
			for (MSG msg:msgs){
				for (Triple t:msg.getTriples()){
					if (t.getPredicate().equals(predicate)){
						count++;
					}
				}
			}
		}
		//Sub graphs
		for (NamedGraph subG:children){
			count+=subG.countPredicate(predicate);
		}
		return count;
	}

	/**
	 * Counts duplicates
	 * 
	 * @return number of duplicates
	 */
	public int countDuplicates(){
		int count=0;
		Collections.sort(triples);
		Triple previous=null;
		for (Triple t:triples){
			if (previous!=null){
				if (t.equals(previous)){
					count++;
					System.err.println("Duplicate: "+t);
				}
			}
			previous=t;
		}
		return count;
	}
	
	/**
	 * Count occurrences of a node (ignores predicates)
	 * 
	 * @param triples	ArrayList of triples to scan
	 * @param node		node value to count
	 * @return			number of occurrences of node in subject/object position
	 */
	public static int countOccurrences(ArrayList<Triple> triples, String node){
		int c=0;
		for (Triple t:triples){
			if (t.getSubject().equals(node)){
				c++;
			}
			if (t.getObject().equals(node)){
				c++;
			}
		}
		return c;
	}
	
	/**
	 * Sorts all children graphs by their name (recursive)
	 */
	public void sortGraphs(){
		Collections.sort(children);
		//Sort sub graphs
		for (NamedGraph subG:children){
			subG.sortGraphs();
		}
	}
	
	/**
	 * Gets graph hierarchy as string
	 * 
	 * @return graph hierarchy string
	 */
	public String getHierarchyString(){
		String hierarchy=name+" {"+depth+"}";
		NamedGraph g=this.parent;
		while (g!=null){
			//add name to string
			hierarchy=g.getName()+" > "+hierarchy;
			//next parent
			g=this.parent;
		}
		//return result
		return hierarchy;
	}
	
	/**
	 * Adds a triple to the graph
	 * 
	 * @param t triple to add
	 */
	public void addTriple(Triple t){
		triples.add(t);
	}
	
	/**
	 * Removes a triple from the graph
	 * 
	 * @param t triple to remove
	 */
	public void removeTriple(Triple t){
		triples.remove(t);
	}
	
	/**
	 * Resolves prefixes in a graph and all subgraphs (recursive) - replaces prefixes with IRIs
	 * 
	 * @param pre ArrayList with prefixes
	 */
	public void resolvePrefixes(LinkedList<Prefix> pre){
		//Resolve prefix in graph name
		if (name.contains(":")){
			//Replace prefix
			for (Prefix p:pre){
				if (name.startsWith(p.getPrefix())){
					name="<"+p.getIriContent()+name.substring(p.getPrefix().length())+">";
					break;
				}
			}
		}
		//Resolve prefixes in triples
		for (Triple t:triples){
			t.resolvePrefixes(pre);
		}
		//Resolve prefixes in MSGs
		if (msgs!=null){
			for (MSG msg:msgs){
				for (Triple t:msg.getTriples()){
					t.resolvePrefixes(pre);
				}
			}
		}
		//Resolve prefixes in sub graphs
		for (NamedGraph subG:children){
			subG.resolvePrefixes(pre);
		}
	}
	
	/**
	 * Applies prefixes to a graph and all subgraphs (recursive) - replaces IRIs with prefixes
	 * 
	 * @param pre ArrayList with prefixes
	 */
	public void applyPrefixes(LinkedList<Prefix> pre){
		//Apply prefix in graph name
		if (name.startsWith("<")){
			//Apply prefix
			for (Prefix p:pre){
				if (name.startsWith("<"+p.getIriContent())){
					name=p.getPrefix()+name.substring(p.getIriContent().length()+1,name.length()-1);
					break;
				}
			}
		}
		//Apply prefixes in triples
		for (Triple t:triples){
			t.applyPrefixes(pre);
		}
		//Apply prefixes in MSGs
		if (msgs!=null){
			for (MSG msg:msgs){
				for (Triple t:msg.getTriples()){
					t.applyPrefixes(pre);
				}
			}
		}
		//Apply prefixes in sub graphs
		for (NamedGraph subG:children){
			subG.applyPrefixes(pre);
		}
	}
	
	/**
	 * Splits graph into MSGs (recursive)
	 */
	public void splitIntoMSGs(){
		/*
		//New MSG ArrayList
		msgs = new ArrayList<MSG>();
		
		//Handle all triples until none are left
		while (!triples.isEmpty()){
			//Create new MSG from first triple
			Triple t=triples.get(0);
			MSG msg=new MSG();
			msgs.add(msg);
			ArrayList<Triple> msgTriples=msg.getTriples();
			msgTriples.add(t);
			triples.remove(t);
			//Check subject (index 0) and object (index 2) of triple for blank nodes
			ArrayList<String> involvedBlankNodes=new ArrayList<String>();
			for (int i=0; i<4; i+=2){
				if (t.getByIndex(i).startsWith("_")){
					if (!involvedBlankNodes.contains(t.getByIndex(i))){
						involvedBlankNodes.add(t.getByIndex(i));
					}
				}
			}			
			//If there are blank nodes: Find triples which contain these and make them part of the MSG
			if (!involvedBlankNodes.isEmpty()){
				Iterator<Triple> it = triples.iterator();
				while (it.hasNext()) {
					Triple checkTriple=it.next();
					//Check subject (index 0) and object (index 2) of triple for blank nodes
					for (int i=0; i<4; i+=2){
						if (involvedBlankNodes.contains(checkTriple.getByIndex(i))){
							//Add triple to current MSG
							msgTriples.add(checkTriple);
							it.remove();
							//Not necessary to check object if subject already contained the blank node
							break;
						}
					}
				}
			}
		}
		
		//Handle all children
		for (NamedGraph g:children){
			g.splitIntoMSGs();
		}
		*/
		
		msgs = new ArrayList<MSG>(triples.size()/2);
		Hashtable<String, MSG> buckets = new Hashtable<String, MSG>();
		
		for (Triple t:triples){
			//Get subject values
			String subject=t.getSubject();
			boolean subjectBN=subject.startsWith("_");
			
			//Get object values
			String object=t.getObject();
			boolean objectBN=object.startsWith("_");
			
			//Add
			if (subjectBN && objectBN){
				//Blank node triples with two blank nodes - find buckets
				MSG subjectBucket=buckets.get(subject);
				MSG objectBucket=buckets.get(object);
				
				if (subjectBucket==null && objectBucket==null){
					//No existing buckets yet - add bucket with two blank nodes
					MSG bucket=new MSG(t);
					msgs.add(bucket);
					buckets.put(subject, bucket);
					buckets.put(object, bucket);
				}else if (subjectBucket!=null && objectBucket==null){
					//Only subject bucket exists
					subjectBucket.addTriple(t);
					buckets.put(object, subjectBucket);
				}else if (subjectBucket==null && objectBucket!=null){
					//Only object bucket exists
					objectBucket.addTriple(t);
					buckets.put(subject, objectBucket);
				}else if (subjectBucket==objectBucket){
					//Both buckets exist and are equal
					subjectBucket.addTriple(t);
				}else{
					//Both buckets exist and they are NOT equal! Need to merge two existing buckets!
					//Update all objectBucket blank nodes to link to subjectBucket
					buckets.put(subject, subjectBucket);
					buckets.put(object, subjectBucket);
					for (Triple tu:objectBucket.getTriples()){
						for (int i=0; i<=2; i+=2){
							if (tu.getByIndex(i).startsWith("_")){
								buckets.put(tu.getByIndex(i), subjectBucket);
							}
						}
					}
					//Remove object bucket
					msgs.remove(objectBucket);
					//Put all statements of objectBucket into subjectBucket and add the current statement
					subjectBucket.addTriples( objectBucket.getTriples() );
					subjectBucket.addTriple(t);
				}
				
			} else if (subjectBN || objectBN){
				//Blank node triples with one blank node - find bucket
				MSG bucket=null;
				if (subjectBN){
					bucket=buckets.get(subject);
				} else {
					bucket=buckets.get(object);
				}
				
				//Add to bucket or create new bucket
				if (bucket!=null){
					//Add to existing
					bucket.addTriple(t);
				}else{
					//Add to new bucket
					bucket=new MSG(t);
					msgs.add(bucket);
					//Add keys
					if (subjectBN){
						buckets.put(subject, bucket);
					}
					if (objectBN){
						buckets.put(object, bucket);
					}
				}
				
			}else{
				//Handle remaining triples without blank nodes
				msgs.add( new MSG(t) );
				if (t.getSubject().startsWith("_") || t.getObject().startsWith("_")){
					System.err.println("something went wrong with "+t);
				}				
			}
			
		}
		
		triples.clear();
		buckets.clear();
		msgs.trimToSize();
		
		//Handle all children
		for (NamedGraph g:children){
			g.splitIntoMSGs();
		}
		
		/*
		//Check if MSGs are okay (find MSGs with same blank nodes)
		HashSet<String> usedBNs=new HashSet<String>();
		for (MSG msg:msgs){
			HashSet<String> msgBNs=new HashSet<String>();
			for (Triple t:msg.getTriples()){
				for (int i=0; i<=2; i+=2){
					String node=t.getByIndex(i);
					if (node.startsWith("_")){
						if (!msgBNs.contains(node)){
							msgBNs.add(node);
							if (usedBNs.contains(node)){
								System.err.println(node+" occurs in distinctive MSGs");
							}else{
								usedBNs.add(node);
							}
						}
					}
				}
			}
			msgBNs.clear();
		}
		System.out.println("MSG COUNT: "+msgs.size());
		int tripleCount=0;
		for (MSG msg:msgs){
			tripleCount+=msg.getTriples().size();
		}
		System.out.println("post statements: "+tripleCount);
		*/
	}
	
	/**
	 * Merges all MSGs back to plain triple lists
	 * All values associated with MSGs (hash, signature, certificate) will get lost
	 */
	public void mergeMSGs(){
		//MSGs?
		if (msgs!=null){
			for (MSG msg:msgs){
				triples.addAll( msg.getTriples() );
			}
			msgs.clear();
			msgs=null;
		}
		
		//Handle all children
		for (NamedGraph g:children){
			g.mergeMSGs();
		}
	}

	/**
	 * Checks if hash value for triples in graph is set (recursive)
	 * Note: function assumes that either all or no triples are hashed, does not check MSGs
	 * 
	 * @return  true if hash value is set, false otherwise
	 */
	public boolean isHashed(){
		//Check triples
		for (Triple t:triples){
			if (t.getHash()!=null){
				return true;
			}else{
				return false;
			}
		}
		//Check sub graphs
		for (NamedGraph sub:children){
			if (!sub.isHashed()){
				return false;
			}
		}
		//Nothing found to hash
		return false;
	}
	
	/**
	 * Checks if there are any MSGs in the {@code NamedGraph}
	 * 
	 * @return true if there are MSGs, false otherwise
	 * 
	 */
	public boolean isUsingMSGs(){
		if (!msgs.isEmpty()){
			return true;
		}else if (!triples.isEmpty()){
			return false;
		}
		//Check sub graphs
		for (NamedGraph sub:children){
			if (sub.isUsingMSGs()){
				return true;
			}
		}
		//Nothing found
		return false;
	}
	
	/**
	 * Adds a MSG signature to this named graph
	 * 
	 * @param data signature data
	 */
	public void addMSGSignature(String[] data){
		if (msgSignatures==null){
			msgSignatures=new ArrayList<String[]>();
		}
		msgSignatures.add(data);
	}
	
	/**
	 * Checks if the graph and all it's content is well-formed
	 * 
	 * @return  true if its well-formed
	 * @throws Exception  if its malformed
	 */
	public boolean isValid() throws Exception {
		//Check triples
		for (Triple t:triples){
			if (!t.isValid()){
				return false;
			}
		}
		
		//Check MSGs
		if (msgs!=null){
			if (triples.size()>0 && msgs.size()>0){
				throw new Exception("Coexisting triple and MSG lists");
			}else{
				for (MSG msg:msgs){
					for (Triple t:msg.getTriples()){
						if (!t.isValid()){
							return false;
						}
					}
				}
			}
		}
		
		//Check children
		for (NamedGraph g:children){
			if (!g.isValid()){
				return false;
			}
		}
		
		//Virtual graph checks
		if (depth==-1){
			if (children.size()>0){
				throw new Exception("Virtual graph has children");
			}
			if (name.length()>0){
				throw new Exception("Virtual graph has a name");
			}
			if (parent!=null){
				throw new Exception("Virtual graph has a parent");
			}
		}
		
		return true;
	}
	
	
	/**
	 * Clears graph by removing all MSGs and sub graphs (recursive)
	 */
	public void clear(){
		triples.clear();
		if (msgs!=null){
			msgs.clear();
		}
		for (NamedGraph sub:children){
			sub.clear();
		}
		children.clear();
	}
	
	/**
	 * Updates the depth of this graphs and all sub graphs (recursive)
	 */
	public void updateDepths(int _depth, NamedGraph _parent){
		if (!(_depth==0 && this.depth==-1)){
			this.depth=_depth;
		}
		parent=_parent;
		for (NamedGraph sub:children){
			sub.updateDepths(_depth+1,this);
		}
	}
	

	//######################################################## Java Functions
	
	/**
	 * Converts the graph to a string (used for printing and debugging)
	 * Attention: May not work properly with very big named graphs
	 * 
	 * @return			string representation
	 */
	public String toString() {
		return this.toString(0);
	}
	
	/**
	 * Converts the graph to a string (used for printing and debugging)
	 * Attention: May not work properly with very big named graphs
	 * 
	 * @param padding	indention level
	 * @return			string representation
	 */
	public String toString(int padding){
		String newLine=System.getProperty("line.separator");
		String result=newLine;
		if (name.length()>0 || triples.size()>0 || msgs!=null || children.size()>0){
			
			//Padding string for proper graph level indentation
			String padStr="";
			for (int i=0; i<padding; i++){
				padStr+="	";
			}
			
			//Graph name & start (virtual graph with depth of -1 is ignored)
			if (depth>=0){
				if (name.length()>0){
					result+=(padStr+name+" {"+newLine);
				}else{
					result+=(padStr+"{"+newLine);
				}
			}
			
			//Triples
			if (depth>=0){
				//Triples of regular (named) graphs
				for (Triple t:triples){
					result+=(padStr+"	"+t+newLine);
				}
			}else{
				//Root triples of virtual graph (no indentation)
				for (Triple t:triples){
					result+=(t+newLine);
				}
			}
			
			//MSGs
			if (msgs!=null){
				if (depth>=0){
					//MSGs of regular (named) graphs
					for (MSG msg:msgs){
						for (Triple msgT:msg.getTriples()){
							result+=(padStr+"	"+msgT+newLine);
						}
						result+=newLine;
					}
				}else{
					//Root MSGs of virtual graph (no indentation)
					for (MSG msg:msgs){
						for (Triple msgT:msg.getTriples()){
							result+=(msgT+newLine);
						}
						result+=newLine;
					}
				}
			}
			
			//Sub graphs
			for (NamedGraph subG:children){
				result+=subG.toString(padding+1);
			}
			
			//Graph end (virtual graph with depth of -1 is ignored)
			if (depth>=0){
				result+=(padStr+"}"+newLine);
			}
		}
		return result;
	}
	
	/**
	 * Compares graph with another graph (used for sorting, lexicographic order)
	 * 
	 * @param g graph to compare this graph with
	 * @return 0 if g is equal, >0 if g is bigger, 0< if g is smaller
	 */
	public int compareTo(NamedGraph g) {
		return name.compareTo(g.name);
	}
	
}
