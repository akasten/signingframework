package de.uni_koblenz.aggrimm.icp.crypto.sign.trigplus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Stack;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;

/**
 * Basic and simplified TriG+ Parser
 * Based on [1]
 * 
 * Note:
 * - ATTENTION: Does NOT support all features TriG/Turtle! Only basic functionality required for the graph signing framework.
 * - supported serializations: TriG+, TriG, Turtle, n-Quads (context is always assumed to be the graph IRI), n-Triples 
 * - TriG Plus (+): Equals TriG but supports nested (named) graphs
 * - not strict and does not follow all details of the original TriG EBNF as described in [1]
 * - optional '=' and '.' for graph definitions are NOT fully supported by this parser
 * - 'a' predicates will be replaced with '<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>' as described in [2] (actually done in 'de.uni_koblenz.aggrimm.icp.crypto.sign.graph.NamedGraph.resolvePrefixes')
 * 
 * Sources:
 * [1] TriG, RDF Dataset Language, W3C First Public Working Draft 09 April 2013, http://www.w3.org/TR/2013/WD-trig-20130409/, 01 June 2013
 * [2] Turtle, Terse RDF Triple Language, W3C Candidate Recommendation 19 February 2013, http://www.w3.org/TR/2013/CR-turtle-20130219/#sec-iri, 01 June 2013
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class TriGPlusReader {
	private static ArrayList<String> line;				//Line data
	private static int l = 0;							//Current line number
	private static int lines = 0;						//Number of lines (equals line.size())
	private static int c = 0;							//Current column
	private static int len = 0;							//Length of current line (equals lc.length())
	private static String lc;							//Line content of current line (equals line.get(l))
	private static char curChar;						//Current character
	private static NamedGraph curGraph;					//Current graph
	private static Stack<NamedGraph> hierarchy;			//Graph hierarchy for nested graphs
	private static GraphCollection gc;					//Graph collection
	private static NamedGraph rootGraph;				//Root graph (graph for triples outside any graph)
	
	/**
	 * Read a file (prefixes are resolved by default).
	 * 
	 * @param path  file path
	 * @return  a new {@link GraphCollection} containing the data read from the provided file
	 * @throws Exception
	 */
	static public GraphCollection readFile(String path) throws Exception {
		return readFile(path, true);
	}
	
    /**
     * Read a file.
     * 
     * @param path  file path
     * @param resolvePrefixes  resolve prefixes (true), or not (false)
     * @return  a new {@link GraphCollection} containing the data read from the provided file
     * @throws Exception
     */
	static public GraphCollection readFile(String path, boolean resolvePrefixes) throws Exception {
		
		//Read file to string vector
		BufferedReader br = new BufferedReader(new FileReader(path));
        String currentLine;
        line = new ArrayList<String>();
        while ((currentLine = br.readLine()) != null) {
        	line.add(currentLine);
        }
        br.close();
        
        //Prepare Parser
        lines=line.size();											//Line Count
        setLine(0);													//Go to line 0
        hierarchy=new Stack<NamedGraph>();							//New empty graph nesting hierarchy
        
        //New graph collection and default graph
        gc=new GraphCollection();									//Graph collection will be filled with graphs and prefixes by the parser and returned at the end
        rootGraph=new NamedGraph("",-1,null);						//Create root graph
        gc.addGraph(rootGraph);										//Add root graph to graph list
        curGraph=null;												//Currently not in any graph (use root graph)
        
        //Iterate lines
        while (l<lines){        	
        	//Iterate chars
        	while (c<len){
        		int[] returnPos1=new int[]{l,c};
        		String[] seq1=parseSequence();
        		int[] returnPos2=new int[]{l,c};
        		String[] seq2=parseSequence();
        		
        		if (seq1[1].length()>0){

        			//'#': Comment
        			if (seq1[1].charAt(0)=='#'){
        				//Skip line
        				setLine(returnPos1[0]); c=len;
        				break;
        				
        			//'@': @prefix/@base
        			}else if (seq1[1].charAt(0)=='@'){
        				if (seq1[1].equals("@prefix")){
        					//@prefix
        					String prefixIri[]=parseSequence();
        					//parseDebug("@prefix "+seq2[1]+" "+prefixIri[1]+" .");
        					gc.addPrefix(new Prefix(seq2[1],prefixIri[1]));
        					//.
        					curChar=peek();
        					if (curChar!='.'){
        						parseError("Expecting '.' literal to end '@prefix' directive");
        					}
        				}else if (seq1[1].equals("@base")){
        					//@base
        					if (!seq2[1].startsWith("<")){
        						parseError("Expecting IRI after '@base' directive (found '"+seq2[1]+"')");
        					}else{
        						//TODO: implement base support
        						//base=seq2[1];
        						parseError("'@base' is not supported by this parser");
        					}
        					//.
        					curChar=peek();
        					if (curChar!='.'){
        						parseError("Expecting '.' literal to end '@base' directive");
        					}
        					
        				}else{
        					parseError("Expecting 'prefix' or 'base' literal after '@' for a directive (found '"+seq1[1].substring(1)+"')");
        				}
        			
        			//'}': Close graph
        			}else if (seq1[1].equals("}")){
        				//parseDebug("close graph: "+curGraph.getName());
        				if (hierarchy.size()>0){
        					hierarchy.pop();
        					if (hierarchy.size()>0){
        						curGraph=hierarchy.peek();
        					}else{
        						curGraph=null;
        					}
        					jumpTo(returnPos2[0],returnPos2[1]);
        				}else{
        					parseError("Unexpected '}' literal. There is no graph which could be closed.");
        				}
        				
        			//'{': Open graph
        			} else if (seq1[1].equals("{") || seq2[1].equals("{") || seq2[1].equals("=")){
        				
        				//Handle optional '='
        				if (seq2[1].equals("=")){
        					returnPos2=new int[]{l,c};
        	        		seq2=parseSequence();
        				}
        				
        				//Get graph name ("" = unnamed, default graph)
        				String graphName;
        				if (seq2[1].equals("{")){
        					//Named graph
        					graphName=seq1[1];
        					c--;
        				}else{
        					//Unnamed graph (use default graph)
        					graphName="";
        					jumpTo(returnPos2[0],returnPos2[1]);
        				}
        				
        				//Get existing graph or add new graph
        				NamedGraph findGraph=null;
        				if (curGraph!=null){
        					for (NamedGraph child:curGraph.getChildren()){
        						if (child.getName().equals(graphName) && child.getDepth()==hierarchy.size()){
        							findGraph=child;
        							break;
        						}
        					}
        				}else{
        					for (NamedGraph child:gc.getGraphs()){
        						if (child.getName().equals(graphName) && child.getDepth()==hierarchy.size()){
        							findGraph=child;
        							break;
        						}
        					}
        				}
        				
    					if (findGraph==null){
    						//Create new graph
    						if (hierarchy.size()==0){
    							//Add graph to graph collection
    							curGraph = new NamedGraph(graphName,0,null);
    							gc.addGraph(curGraph);
    						}else{
    							//Add graph as child to other graph
    							curGraph = new NamedGraph(graphName,hierarchy.size(),hierarchy.peek());
    						}
    					}else{
    						//Use graph which has been found
    						curGraph = findGraph;
    					}
    					hierarchy.push(curGraph);
    					//parseDebug("open graph: "+curGraph.getName());
        			
        			//Triple/Quad
        			}else{
        				
        				String t[]=new String[3];
        				//triples ::= subject predicateObjectList | blankNodePropertyList predicateObjectList?
        				if (seq1[0].equals("[")){
        					//'[' implies: blankNodePropertyList predicateObjectList?
        					//TODO: Implement parsing for this case
        				}else{
        					//No '[' implies: subject predicateObjectList
        					//subject ::= iri | blank
        					c=returnPos2[1];
        					t[0]=seq1[1];				//set subject
       						//predicateObjectList
        					parsePredicateObjectList(t);
        				}
        				
        			}
        		}
	        	
	        	//Next char
	        	c++;
        	}
        	//Next line
        	setLine(l+1);
        }
        
        //Resolve prefixes after loading?
        if (resolvePrefixes){
        	gc.resolvePrefixes();
        }
        
        //Return graph collection
        return gc;
	}
	
	/**
	 * Set line
	 * 
	 * @param lineIndex  line to jump to
	 */
	private static void setLine(int lineIndex){
		l=lineIndex;
		if (lineIndex<lines){
			lc=line.get(l);
		}else{
			lc="";
		}
		len=lc.length();
		c=0;
	}
	
	/**
	 * Jump to specified line and column
	 * 
	 * @param lineIndex  line to jump to
	 * @param column  column to jump to
	 */
	private static void jumpTo(int lineIndex, int column){
		if (lineIndex!=l){
			setLine(lineIndex);
		}
		c=column;
	}
	
	/**
	 * Skip whitespaces / linebreaks and get first non whitespace character
	 * 
	 * @return first non whitespace character, ' ' when failed
	 */
	private static char peek(){
		//Iterate lines
        while (l<lines){
        	//Iterate chars
        	while (c<len){
        		char curChar=lc.charAt(c);
        		//Not a whitespace char? Return it!
        		if (!Character.isWhitespace(curChar)){
        			return curChar;
        		}
        		//Next char
        		c++;
        	}
        	//Next line
        	setLine(l+1);
        }
		//Failed to find non whitespace char
		return ' ';
	}
	
	/**
	 * Parse Error
	 * 
	 * @param message  error message to show
	 * @throws Exception  always throws an exception with the specified message
	 */
	private static void parseError(String message) throws Exception{
		throw new Exception("TriG+ Parser Error ("+l+":"+c+"): "+message);
	}
	
	/**
	 * Write Debug Message
	 * 
	 * @param message  debug message to show
	 */
	@SuppressWarnings("unused")
	private static void parseDebug(String message) {
		System.out.println("TriG+ Parser Debug ("+l+":"+c+"): "+message);
	}
	
	/**
	 * Parse predicateObjectList
	 * predicateObjectList ::= verb objectList (';' (verb objectList)?)*
	 * verb ::= predicate | 'a'
	 * predicate	::=	iri
	 * objectList ::= object (',' object)*
	 * object ::= iri | blank | blankNodePropertyList | literal
	 * 
	 * @param t
	 * @throws Exception  if predicateObjectList can not be parsed because it is malformed 
	 */
	private static void parsePredicateObjectList(String[] t) throws Exception {
		while (true){
			//Get verb/predicate
			String[] seq1=parseSequence();
			t[1]=seq1[1];			//set predicate
			
			//Handle objectList
			//objectList ::= object (',' object)*
			//object ::= iri | blank | blankNodePropertyList | literal
			boolean comma=true;
			while (comma){
				comma=false;
				
				int oldL=l;
				int oldC=c;
				String complexSeq=parseComplexSequence();
				int newL=l;
				int newC=c;
				
				//System.out.println("complex sequence: "+complexSeq);
				
				//'[': Expect a 'predicateObjectList' here
				if (complexSeq.startsWith("[")){
					
					//System.out.println("blankNodePropertyList detected: "+complexSeq);
					
					//Handle nested predicateObjectList
					setLine(oldL);
					c=oldC+1;
					parsePredicateObjectList(new String[]{t[2], "", ""});
					setLine(newL);
					c=newC;
					//Check if there is a comma
					int returnPos=c;
					char curChar=peek();
					if (curChar==','){
						comma=true;
					}else{
						c=returnPos;
					}
				//No '[': Simple stuff
				}else{
					//Check if there is a comma
					if (complexSeq.endsWith(",")){
						comma=true;
						complexSeq=complexSeq.substring(0, complexSeq.length()-1);
					}else{
						int returnPos=c;
						char curChar=peek();
						if (curChar==','){
							comma=true;
						}else{
							c=returnPos;
						}
					}
					//Object
					t[2]=complexSeq;
					
					//Check next char to see if there is just a triple or a quad
					int returnPos=c;
					char curChar=peek();
					
					//Triples can be ended with ',', ';', '.' or '}' at this point
					//Expect a quad in all other cases! 
					if (!comma && curChar!=';' && curChar!='.' && curChar!='}'){
						//Get quad context
						String context=parseSequence()[1];
						//Add Quad!
						addQuad(t[0],t[1],t[2],context);
					}else{
						//Add Triple!
						c=returnPos;
						addTriple(t[0],t[1],t[2]);
					}
					
				}				
			}

			//Expecting either '.' or '}' to end triple definition or ';' for more predicates and objects
			//Break at everything which is not ';' to avoid infinite loops in malformed files
			curChar=peek();
			if (curChar!=';'){
				//No ';': Cancel current subject
				if (curChar!='.' && curChar!='}'){
					parseError("Expecting '.' or ';' to end triple definition (found '"+curChar+"')");
				}
				return;
			}else{
				//';': Continue with current subject
				c++;
			}
		}
	}
	
	/**
	 * Parse next sequence (single line only but may skip to another line)
	 * 
	 * @return  string array with length 3: [0]: start delimiter, [1]: content, [2]: end delimiter
	 */
	private static String[] parseSequence() {
		String[] result=new String[3];
		boolean quotedLiteral=false;
		//Go to next non-whitespace character
		curChar=peek();
		//Get delimiter
		switch (curChar){
			case '<':
				result[0]="<";
				result[2]=">";
				break;
			case '[':
				result[0]="[";
				result[2]="]";
				break;
			case '(':
				result[0]="(";
				result[2]=")";
				break;
			case '"':
				result[0]="\"";
				result[2]="\"";
				if (c+5<=len){
					if (lc.charAt(c+1)=='"' && lc.charAt(c+2)=='"'){
						result[0]="\"\"\"";
						result[2]="\"\"\"";
					}
				}
				quotedLiteral=true;
				break;
			case '\'':
				result[0]="'";
				result[2]="'";
				if (c+5<=len){
					if (lc.charAt(c+1)=='\'' && lc.charAt(c+2)=='\''){
						result[0]="'''";
						result[2]="'''";
					}
				}
				quotedLiteral=true;
				break;
			default:
				result[0]="";
				result[2]="";
		}
		//Extract sequence
		int start=c;
		c+=result[0].length();
		int endLength=result[2].length();
		for (; c<len; c++){
			if (endLength==0){
				//End at whitespace
				curChar=lc.charAt(c);
        		if (Character.isWhitespace(curChar)){
        			c++;
        			result[1]=lc.substring(start,c-1);
        			return result;
        		}
			}else{
				//End at string
				if (lc.substring(c,c+endLength).equals(result[2])){
					//Ignore quotes which are masked with '\'
					if (quotedLiteral){
						if (c>0){
							if (lc.charAt(c-1)=='\\'){
								continue;
							}
						}
					}
					c+=endLength;
					//Quoted literals may have language/datatype
					if (quotedLiteral){
						if (c+endLength+2<len){
							if ((lc.substring(c+endLength-1,c+endLength).equals("@"))||(lc.substring(c+endLength-1,c+endLength+1).equals("^^"))){
								endLength=0;
							}
						}
					}
					//End (only if no language/datatype has been found, otherwise wait for next whitespace)
					if (endLength!=0){
						result[1]=lc.substring(start,c+endLength-1);
						return result;
					}
				}
			}
		}
		//Failed
		c++;
		result[1]=lc.substring(start);
		return result;
	}
	
	/**
	 * Parse a complex sequence (multiple lines)
	 * 
	 * @return  complex sequence string
	 */
	private static String parseComplexSequence() {
		//Go to next non-whitespace character
		curChar=peek();
		//Is there a '['?
		if (curChar=='['){
			//Yes, starting with '['! Complex parsing required!
			c++;
			int squareBracketLevel=1;				//square bracket depth level (starting at 1 because there already was '[')
			String result="[";						//result sequence
			//Search ']' which closes the first '['
			while (true){
				if (c<len){
					//Get char
					curChar=lc.charAt(c);
				}else{
					//Next line
					while(l<lines){
						setLine(l+1);
						if (c<len){
							curChar=lc.charAt(c);
							break;
						}
					}
					//End of file reached
					if (l>=lines){
						return result;
					}
				}
				//Add char to result sequence
				result+=curChar;
				//Handle square brackets
				if (curChar=='['){
					//Opening square bracket: increase square bracket level
					squareBracketLevel++;
				}else if (curChar==']'){
					//Closing square bracket: decrease square bracket level
					squareBracketLevel--;
					//End in case that this was the square bracket which ends the sequence
					if (squareBracketLevel==0){
						c++;
						return result;
					}
				}
				//Next char
				c++;
			}
		}else{
			//No, not starting with '['! This is a simple sequence!
			return parseSequence()[1];
		}
	}
	
	/**
	 * Add triple
	 * Add either to current graph or to default graph
	 * 
	 * @param subject  subject of new triple
	 * @param predicate  predicate of new triple
	 * @param object  object of new triple
	 */
	private static void addTriple(String subject, String predicate, String object){
		if (curGraph!=null){
			//Currently in a graph, add to this graph
			curGraph.addTriple(new Triple(subject, predicate, object));
		}else{
			//Currently not in any graph, add to root graph
			rootGraph.addTriple(new Triple(subject, predicate, object));
		}
		//System.out.println("triple: "+subject+" "+predicate+" "+object+" .");
	}
	
	/**
	 * Add quad
	 * Graph is defined by context
	 * 
	 * @param subject  subject of new triple
	 * @param predicate  predicate of new triple
	 * @param object  object of new triple
	 * @param context  name of graph this triple will be added to
	 */
	private static void addQuad(String subject, String predicate, String object, String context){
		//Get graph
		NamedGraph graph=null;
		for (NamedGraph g:gc.getGraphs()){
			if (g.getDepth()==0 && g.getName().equals(context)){
				graph=g;
				break;
			}
		}
		//Create graph if it has not been found yet
		if (graph==null){
			graph = new NamedGraph(context,0,null);
			gc.addGraph(graph);
		}
		//Add triple
		graph.addTriple(new Triple(subject, predicate, object));
	}
}
