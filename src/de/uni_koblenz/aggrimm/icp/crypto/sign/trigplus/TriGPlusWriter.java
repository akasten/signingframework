package de.uni_koblenz.aggrimm.icp.crypto.sign.trigplus;

import java.io.BufferedWriter;
import java.io.FileWriter;

import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.*;

/**
 * Basic TriG+ Writer. Writes a {@link GraphCollection} to a file.
 * 
 * @author <a href="mailto:schauss@uni-koblenz.de">Peter Schauß</a>
 */
public class TriGPlusWriter {

	/**
	 * Writes a {@link GraphCollection} to a file (prefixes are applied by
	 * default).
	 * 
	 * @param gc
	 *            {@link GraphCollection} to write
	 * @param path
	 *            file name and path
	 * @throws Exception
	 */
	public static void writeFile(GraphCollection gc, String path)
			throws Exception {
		writeFile(gc, path, true);
	}

	/**
	 * Writes a {@link GraphCollection} to a file.
	 * 
	 * @param gc
	 *            {@link GraphCollection} to write
	 * @param path
	 *            file name and path
	 * @param applyPrefixes
	 *            boolean, true if prefixes shall be applied, false otherwise
	 * @throws Exception
	 */
	public static void writeFile(GraphCollection gc, String path,
			boolean applyPrefixes) throws Exception {
		// Apply Prefixes
		if (applyPrefixes) {
			gc.applyPrefixes();
		}

		// Write file
		BufferedWriter bw = new BufferedWriter(new FileWriter(path));

		// Write prefixes to file
		for (Prefix p : gc.getPrefixes()) {
			bw.write(p.toString());
		}

		// Write graphs to file
		for (NamedGraph g : gc.getGraphs()) {
			writeGraph(bw, g, 0);
		}

		// Close file
		bw.close();
	}

	/**
	 * Writes a {@link NamedGraph} to a BufferedWriter (recursive).
	 * 
	 * @param bw
	 *            BufferedWriter to write to
	 * @param g
	 *            {@link NamedGraph} to write
	 * @param padding
	 *            indentation level (number of tabs)
	 * @throws Exception
	 */
	public static void writeGraph(BufferedWriter bw, NamedGraph g, int padding)
			throws Exception {
		// Skip graphs which have no name and are empty
		if (g.getName().length() > 0 || g.getTriples().size() > 0
				|| g.getMSGs() != null || g.getChildren().size() > 0) {

			// Padding string for proper graph level indentation
			String padStr = "";
			for (int i = 0; i < padding; i++) {
				padStr += "	";
			}

			// Graph name & start (virtual graph with depth of -1 is ignored)
			if (g.getDepth() >= 0) {
				// Regular (named) graphs
				String graphName = g.getName();
				if (graphName.length() > 0) {
					bw.write(padStr + graphName + " {");
				}
				else {
					bw.write(padStr + "{");
				}
				bw.newLine();
			}

			// Triples
			if (g.getDepth() >= 0) {
				// Triples of regular (named) graphs
				for (Triple t : g.getTriples()) {
					bw.write(padStr + "	" + t);
					bw.newLine();
				}
			}
			else {
				// Root triples of virtual graph (no indentation)
				for (Triple t : g.getTriples()) {
					bw.write(t.toString());
					bw.newLine();
				}
			}

			// MSGs
			if (g.getMSGs() != null) {
				if (g.getDepth() >= 0) {
					// MSGs of regular (named) graphs
					for (MSG msg : g.getMSGs()) {
						for (Triple msgT : msg.getTriples()) {
							bw.write(padStr + "	" + msgT);
							bw.newLine();
						}
						bw.newLine();
					}
				}
				else {
					// Root MSGs of virtual graph (no indentation)
					for (MSG msg : g.getMSGs()) {
						for (Triple msgT : msg.getTriples()) {
							bw.write(msgT.toString());
							bw.newLine();
						}
						bw.newLine();
					}
				}
			}

			// Sub graphs
			for (NamedGraph subG : g.getChildren()) {
				writeGraph(bw, subG, padding + 1);
			}

			// Graph end (virtual graph with depth of -1 is ignored)
			if (g.getDepth() >= 0) {
				bw.write(padStr + "}");
				bw.newLine();
			}
		}
	}

}
