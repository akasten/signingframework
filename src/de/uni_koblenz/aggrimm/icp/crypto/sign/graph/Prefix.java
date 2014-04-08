package de.uni_koblenz.aggrimm.icp.crypto.sign.graph;

/**
 * Prefixes are used to reduce the file size of graph serializations by shortening IRIs.
 * 
 * Full IRI notation:			<IRI>
 * Shortened IRI notation:		prefixID:suffixString
 * Prefix notation:				@prefix prefixID: <prefixIRI> .
 * 
 * To convert shortened IRIs to full IRIs 'prefixID:' is replaced with the corresponding prefixIRI:
 * prefixID:suffixString -> <prefixIRIsuffixString>
 * 
 * Example:
 * '@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .' 
 * 'rdfs:example1 rdfs:type "bla"'
 * 
 * Result:
 * <http://www.w3.org/2000/01/rdf-schema#example1> <http://www.w3.org/2000/01/rdf-schema#type> "bla"
 * 
 * Actual replacement is done in the following methods:
 * Resolve: GraphCollection.resolvePrefixes, NamedGraph.resolvePrefixes, Triple.resolvePrefixes
 * Apply: GraphCollection.applyPrefixes, NamedGraph.applyPrefixes,  Triple.applyPrefixes
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class Prefix {
	private String prefix;					//Prefix (including ":" at end)
	private String iri;						//IRI (including starting "<" and ending ">")
	
	//######################################################## Constructors
	
	/**
	 * Creates a new prefix
	 * Also ensures that prefix always ends with ":" and that iri starts with "<" and ends with ">"
	 * 
	 * @param prefix
	 * @param iri
	 */
	public Prefix(String prefix, String iri) {
		//Prefix: Add ":" if necessary
		if (!prefix.endsWith(":")){
			prefix+=":";
		}
		//IRI: Add "<" and ">" if necessary
		if (!iri.startsWith("<")){
			iri="<"+iri;
		}
		if (!iri.endsWith(">")){
			iri+=">";
		}
		//Set
		this.prefix = prefix;
		this.iri = iri;
	}
	
	//######################################################## Getters & Setters
	
	public String getPrefix() {
		return prefix;
	}
		
	public String getIri() {
		return iri;
	}
	
	/**
	 * Gets actual IRI content without "<" and ">"
	 * 
	 * @return IRI content without "<" and ">"
	 */
	public String getIriContent(){
		return iri.substring(1,iri.length()-1);
	}
	
	//######################################################## Java Functions
	
	//toString (used for printing, debugging and writing to files)
	public String toString() {
		return String.format("@prefix %s %s .%n", prefix, iri);
	}
	
	//compareTo (used for sorting, lexicographic order)
	public int compareTo(Prefix p) {
		int ret = prefix.compareTo(p.getPrefix());
		if (ret != 0){
			return ret;
		}else{
			return iri.compareTo(p.getIri());
		}
	}
	
}
