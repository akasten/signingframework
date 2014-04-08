package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.generic;

import java.util.Iterator;
import java.util.ArrayList;
import java.util.LinkedList;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;
import de.uni_koblenz.aggrimm.icp.crypto.sign.ontology.Ontology;

/**
 * Standard {@link GraphCollection} assembler
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class Assembler {
	
	/**
	 * Assembles a {@link GraphCollection}, adds signature by default
	 * Adds a signature graph with signature statements to the {@link GraphCollection}.
	 * 
	 * @param gc					{@link GraphCollection} to assemble
	 * @param signatureGraphName	name of signature graph
	 * @throws Exception
	 */
	public static void assemble(GraphCollection gc, String signatureGraphName) throws Exception {
		assemble(gc, signatureGraphName, true);
	}
	
	/**
	 * Assembles a {@link GraphCollection}
	 * Adds a signature graph with signature statements to the {@link GraphCollection}.
	 * 
	 * @param gc					{@link GraphCollection} to assemble
	 * @param signatureGraphName	name of signature graph
	 * @param addSignature			add signature statement to graph?
	 * @throws Exception
	 */
	public static void assemble(GraphCollection gc, String signatureGraphName, Boolean addSignature) throws Exception {
		//Get Signature Data
		SignatureData sigData=gc.getSignature();
		
		//Prepare Ontology
		Ontology o=new Ontology(sigData);
		
		//Choose an unused prefix for signatures to avoid prefix collisions
		//Add number to default prefix in case it is used in graph already with other IRI
		String sigPrefix=o.getSigPrefix();			//Get signature prefix from Ontology
		String sigIri=Ontology.getSigIri();			//Get signature IRI from Ontology
		String sigPre=sigPrefix;
		for (int prefixCounter=2; true; prefixCounter++ ){
			//Find equal prefix with different IRI
			boolean prefixUsed=false;
			for (Prefix p:gc.getPrefixes()){
				if (p.getPrefix().equals(sigPre)){
					if (!p.getIri().equals("<"+sigIri+">")){
						//Found!
						prefixUsed=true;
						break;
					}
				}
			}
			if (prefixUsed){
				//Prefix is used with different IRI! Try again with another one (add higher number)!
				sigPre=sigPrefix+prefixCounter;
			}else{
				//Prefix is not used with a different IRI! Continue!
				break;
			}
		}
		o.setSigPrefix(sigPre);
		
		//Wrap a signature graph around everything
		LinkedList<NamedGraph> temp = gc.getGraphs();							//Cache old root level graph list
		NamedGraph sigGraph=new NamedGraph(signatureGraphName,0,null);			//Create signature graph
		sigGraph.setChildren(temp);												//Put old graphs into signature graph
		LinkedList<NamedGraph> graphs=new LinkedList<NamedGraph>();				//New list for graphs at root level
		graphs.add(new NamedGraph("",-1,null));									//Add virtual graph
		graphs.add(sigGraph);													//Add signature graph
		gc.setGraphs(graphs);													//Set this list as new root level graph list
		
		//Copy root level triples (in old root level virtual graph)
		ArrayList<Triple> rootTriples = new ArrayList<Triple>();
		Iterator<NamedGraph> it = temp.iterator();
		while (it.hasNext()) {
			NamedGraph checkGraph=it.next();
			//Is virtual graph?
			if (checkGraph.getDepth()==-1 && checkGraph.getName().length()==0){
				//Triples
				for (Triple t:checkGraph.getTriples()){
					rootTriples.add(t);
				}
				//MSGs
				if (checkGraph.getMSGs()!=null){
					for (MSG msg:checkGraph.getMSGs()){
						for (Triple t:msg.getTriples()){
							rootTriples.add(t);
						}
					}
				}
				it.remove();
				break;
			}
		}
		//Update depths of modified graph collection
		gc.updateDepths();														
		
		//Add signature triples from onotology
		ArrayList<Triple> sigGraphTriples=sigGraph.getTriples();
		LinkedList<Triple> signatureTriples;
		if (addSignature){
			signatureTriples=o.getTriples();
		}else{
			signatureTriples=o.getTriplesWithoutSignature();
		}
		for (Triple t:signatureTriples){
			sigGraphTriples.add( new Triple(t.getSubject(),t.getPredicate(),t.getObject()) );
		}
		
		//Add old root triples
		for (Triple t:rootTriples){
			sigGraphTriples.add(t);
		}
		
		//Add signature prefix
		gc.addPrefix(new Prefix(sigPre+":","<"+sigIri+">"));
		gc.applyPrefixes();
	}
	
}
