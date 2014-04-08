package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

import java.math.BigInteger;
import java.util.LinkedList;

/**
 * A (RDF) triple or statement consists of a subject, a predicate and an object.
 * A hash value and an annotation can be saved as well (used by some but not all algorithms).
 * 
 * Properties of subject/predicate/object:
 * 
 * - Subjects and objects can either be IRIs, blank nodes or literals
 * - Predicates can only be IRIs or "a" ("a" equals "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>")
 * 
 * - IRIs always start with "<" and end with ">" unless they are using a prefix
 * - Prefixed IRIs start with a prefix string followed by a colon (":") and a suffix string (no whitespaces in any of those)
 * - Prefixed IRIs may have no prefix and/or no suffix (so the shortest possible prefixed IRI is just a colon)
 * - Prefixed IRIs are commonly resolved after loading a graph and applied again before saving it
 * 
 * - Blank nodes start with _: followed by an identifier string (no whitespaces in the identifier string)
 * 
 * - Literals always start with double quotes
 * - Literals end with double quotes but may have one language ("^^") and/or one datatype ("@") attachment
 * - Language attachments are introduced with "^^" directly after the ending double quotes or data type attachments (no whitespaces)
 * - Data type attachments are introduced with "@" directly after the ending double quotes or language attachments (no whitespaces)
 * - Language and data type attachments cannot contain any whitespaces (whitespaces are used during parsing to end them)
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class Triple implements Comparable<Triple> {
	//Indices
	public static final int subject = 0;		//Triple Subject (index 0)
	public static final int predicate = 1;		//Triple Predicate (index 1)
	public static final int object = 2;			//Triple Object (index 2)
	public static final int annotation = 3;		//Annotation/comment in this line (used by some signing algorithms as temporary cache, index 3)
	
	//Data
	private String[] data;						//Array containing the actual data (subject/predicate/object/annotation strings, length: 4)
	private BigInteger hash;					//Cached hash (used by Fisteus 2010 algorithm)
	
	//######################################################## Constructors

	/**
	 * Constructor: Create new triple from subject/predicate/object strings (annotation will be empty)
	 * 
	 * @param subject
	 * @param predicate
	 * @param object
	 */
	public Triple(String subject, String predicate, String object) {
		data = new String[4];
		data[Triple.subject] = subject;
		data[Triple.predicate] = predicate;
		data[Triple.object] = object;
		data[Triple.annotation] = "";
	}
	
	/**
	 * Constructor: Create new triple from subject/predicate/object/annotation strings
	 * 
	 * @param subject
	 * @param predicate
	 * @param object
	 * @param annotation
	 */
	public Triple(String subject, String predicate, String object,String annotation) {
		data = new String[4];
		data[Triple.subject] = subject;
		data[Triple.predicate] = predicate;
		data[Triple.object] = object;
		data[Triple.annotation] = annotation;
	}
	
	//######################################################## Getters & Setters
	public String getSubject() {
		return data[Triple.subject];
	}

	public void setSubject(String subject) {
		data[Triple.subject] = subject;
	}

	public String getPredicate() {
		return data[Triple.predicate];
	}

	public void setPredicate(String predicate) {
		data[Triple.predicate] = predicate;
	}

	public String getObject() {
		return data[Triple.object];
	}

	public void setObject(String object) {
		data[Triple.object] = object;
	}

	public String getAnnotation() {
		return data[Triple.annotation];
	}

	public void setAnnotation(String annotation) {
		data[Triple.annotation] = annotation;
	}

	/**
	 * Get subject/predicate/object/annotation by integer index
	 * 
	 * @param index  0=subject, 1=predicate, 2=object, 3=annotation
	 * @return  subject/predicate/object/annotation as string
	 */
	public String getByIndex(int index) {
		return data[index];
	}
	
	/**
	 * Set subject/predicate/object/annotation by integer index
	 *  
	 * @param index
	 * @param value
	 */
	public void setByIndex(int index, String value) {
		data[index] = value;
	}
	
	public BigInteger getHash() {
		return hash;
	}

	public void setHash(BigInteger hash) {
		this.hash = hash;
	}
	
	//######################################################## Helper Functions

	/**
	 * Are subject, predicate and object equal (don't check the annotation)?
	 * 
	 * @param t  Triple which is compared with this triple
	 * @return  true if subject, predicate and object of both triples are equal, false otherwise
	 */
	public boolean isSPOequal(Triple t){
		for (int i=0; i<3; i++){
			if ( !data[i].equals(t.getByIndex(i)) ){
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Are subject, predicate and object equal (don't check the annotation)?
	 * 
	 * @param triple  Triple (specified as string array) which is compared with this triple
	 * @return  true if subject, predicate and object of both triples are equal, false otherwise
	 */
	public boolean isSPOequal(String triple[]){
		for (int i=0; i<3; i++){
			if ( !data[i].equals(triple[i]) ){
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Checks if tripel is well-formed
	 * 
	 * @return  true if triple is well-formed
	 * @throws Exception  if triple is malformed
	 */
	public boolean isValid() throws Exception {
		if (this.getSubject().length()==0){
			throw new Exception("Empty subject ("+this+")");
		}
		if (this.getPredicate().length()==0){
			throw new Exception("Empty predicate ("+this+")");
		}
		if (this.getObject().length()==0){
			throw new Exception("Empty object ("+this+")");
		}
		return true;
	}
	
	/**
	 * Resolve Prefixes in triple - replaces prefixes with IRIs
	 * 
	 * @param pre
	 */
	public void resolvePrefixes(LinkedList<Prefix> pre){
		//Scan subject, predicate and object (data indices 0 to 2)
		for (int i=0; i<3; i++){
			String value=getByIndex(i);
			//Contains ':'? (a prefix)
			if (value.contains(":")){
				//Replace prefix
				for (Prefix p:pre){					
					if (value.startsWith(p.getPrefix())){
						setByIndex(i,"<"+p.getIriContent()+value.substring(p.getPrefix().length())+">");
						break;
					}
				}
			//Is predicate? (array position 1)
			}else if (i==1){
				//Replace 'a' predicate
				if (value.equals("a")){
					setPredicate("<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>");
				}
			}
		}
	}
	
	/**
	 * Apply Prefixes to triple - replaces IRIs with prefixes
	 * 
	 * @param pre
	 */
	public void applyPrefixes(LinkedList<Prefix> pre){
		//Scan subject, predicate and object (data indices 0 to 2)
		for (int i=0; i<3; i++){
			String value=getByIndex(i);
			//Starts with '<'? (IRI)
			if (value.startsWith("<")){
				//'a' predicate
				if (i==1 && value.equals("<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>")){
					setPredicate("a");
				}else{
					//Try to find matching prefix
					for (Prefix p:pre){
						if (value.startsWith("<"+p.getIriContent())){
							//Replace IRI with prefix
							setByIndex(i,p.getPrefix()+value.substring(p.getIriContent().length()+1,value.length()-1));
							//Only one prefix can match! Break!
							break;
						}
					}
				}
			}
		}
	}
	
	//######################################################## Java Functions
	
	/**
	 * Converts triple to a string (used for printing and debugging)
	 * 
	 * @return			string representation
	 */
	public String toString() {
		if (data[Triple.annotation].length() > 0){
			return data[Triple.subject]+" "+data[Triple.predicate]+" "+data[Triple.object]+" . #"+data[Triple.annotation];
		}else{
			return data[Triple.subject]+" "+data[Triple.predicate]+" "+data[Triple.object]+" .";
		}
	}
	
	/**
	 * Compare this triple with another triple
	 * used for sorting, lexicographic order, ignores annotations
	 * 
	 * @param 			triple to compare with
	 * @return			value expressing relation of the triples
	 */
	public int compareTo(Triple t) {
		int ret = 0;
		//compare order: subject -> predicate -> object
		for (int i=0; i<3; i++){
			ret = data[i].compareTo(t.getByIndex(i));
			if (ret != 0){
				return ret;
			}
		}
		return ret;
	}
	
	/**
	 * Checks if this triple is equal to another triple
	 * 
	 * @param o {@link Triple} to compare with
	 * @return  true if equal, false otherwise
	 */
	public boolean equals(Object o) {
		if (o==null){
			return false;
		} else if (this==o){
			return true;
		} else if (this.getClass() != o.getClass()){
			return false;
		} else {
			Triple c=(Triple)o;
			for (int i=0; i<3; i++){
				if (!data[i].equals(c.getByIndex(i))){
					return false;
				}
			}
			return true;
		}
	}
	
}
