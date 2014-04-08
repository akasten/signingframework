package de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.auxiliary;

/**
 * Simple "GenSymCounter".
 * A counter which creates strings with leading zeros as output.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class GenSymCounter {
	private int length;				//Required max. length in characters/digits (String will be padded with zeros to always reach this length)
	private int counter;			//Current counter value
	private int initialValue;		//Initial value (defaults to 0)
	private int maxValue;			//Highest allowed value
	
	//######################################################## Constructor
	
	/**
	 * Standard Constructor with maxValue and initialValue (first value of {@link #getNewSym} is initialValue+1).
	 * 
	 * @param maxValue			maximum value of the counter
	 * @param initialValue		initial value (first value of {@link #getNewSym} will be this+1)
	 */
	public GenSymCounter(int maxValue, int initialValue) {
		this.length = Integer.toString(maxValue).length();
		this.counter = initialValue;
		this.initialValue = initialValue;
		this.maxValue = maxValue;
	}
	
	/**
	 * Constructor with maxValue only, initialValue defaults to 0 (first value of {@link #getNewSym} is 1).
	 * 
	 * @param maxValue			maximum value of the counter
	 */
	public GenSymCounter(int maxValue) {
		this.length = Integer.toString(maxValue).length();
		this.counter = 0;
		this.initialValue = 0;
		this.maxValue = maxValue;
	}
	
	//######################################################## Methods
	
	/**
	 * Gets a new symbol by increasing the counter and returning its value in string representation.
	 * 
	 * @return					string containing the counter value with leading zeros 
	 * @throws Exception
	 */
	public String getNewSym() throws Exception{
		//Increase Counter
		counter++;
		if (counter>maxValue){
			throw (new Exception("Counter value ("+counter+") exceeds maximum value ("+maxValue+")"));
		}
		//Return
		return createSymStringFromInt(counter);
	}
	
	/**
	 * Gets the current symbol (counter value in string representation).
	 * 
	 * @return					string containing the counter value with leading zeros
	 */
	public String getCurrentSym(){
		return createSymStringFromInt(counter);
	}
	
	/**
	 * Gets the current counter value as integer.
	 * 
	 * @return					current counter value
	 */
	public int getCurrentValue(){
		return counter;
	}
	
	/**
	 * Creates a string representation for integer value (cast int to string and pad with leading zeros to fit length).
	 * 
	 * @param value				a number
	 * @return					string containing the value with leading zeros, length depending on {@code maxValue}
	 */
	public String createSymStringFromInt(int value){
		//Create String from integer value
		String s = Integer.toString(value);
		//Pad string with leading zeros
		int l = s.length();
		while (l<length){
			s="0"+s;
			l++;
		}
		//Return the resulting padded string
		return s;
	}
	
	/**
	 * Resets the counter to {@code initialValue}. 
	 */
	public void reset(){
		counter=initialValue;
	}
	
}
