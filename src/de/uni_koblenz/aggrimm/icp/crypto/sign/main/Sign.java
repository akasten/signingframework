package de.uni_koblenz.aggrimm.icp.crypto.sign.main;

import java.security.KeyPair;

import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.SignatureAlgorithmInterface;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.SignatureAlgorithmList;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.GraphCollection;
import de.uni_koblenz.aggrimm.icp.crypto.sign.trigplus.TriGPlusReader;
import de.uni_koblenz.aggrimm.icp.crypto.sign.trigplus.TriGPlusWriter;

public class Sign {

	private static String envHashAlgorithm = "sha-256";

	private static void checkNull(Object obj, String errorMsg) {
		if (obj == null) {
			System.err.println(errorMsg);
			System.exit(-2);
		}
	}

	public static void main(String[] args) {
		if (args.length != 10) {
			System.out
					.println("Wrong number of parameters. All following parameters must be set in arbitrary order: ");
			System.out.println(" -i  input graph");
			System.out.println(" -o  output graph");
			System.out.println(" -sk file name of secret (private) key ");
			System.out.println(" -pk file name of public key ");
			System.out.println(" -c  framework configuration");
			System.out.println("     possible values:");
			System.out.println("       carroll-2003");
			System.out.println("       fisteus-2010");
			System.out.println("       sayers-2004");
			System.out.println("       tummarello-2005");

			System.exit(1);
		}

		Sign signer = new Sign();

		String privKey = null;
		String pubKey = null;
		String configuration = null;
		String inputGraph = null;
		String outputGraph = null;

		for (int i = 0; i < args.length; ++i)
			switch (args[i]) {
				case "-i":
					inputGraph = args[i + 1];
					break;
				case "-o":
					outputGraph = args[i + 1];
					break;
				case "-c":
					configuration = args[i + 1];
					break;
				case "-sk":
					privKey = args[i + 1];
					break;
				case "-pk":
					pubKey = args[i + 1];
					break;
			}

		checkNull(inputGraph, "Input graph missing.");
		checkNull(outputGraph, "Output graph missing.");
		checkNull(configuration, "Framework configuratuon missing.");
		checkNull(pubKey, "Public key missing.");
		checkNull(privKey, "Private key missing.");

		KeyPair keyPair = null;
		try {
			keyPair = new RSAKeyPair(privKey, pubKey).getKeyPair();
		}
		catch (Exception e) {
			System.err.println("Invalid key pair.");
			// e.printStackTrace();
			System.exit(-3);
		}

		SignatureAlgorithmInterface config = null;
		try {
			config = SignatureAlgorithmList.getAlgorithm(configuration);
		}
		catch (Exception e) {
			System.err.println("Unknown framework configuration.");
			// e.printStackTrace();
			System.exit(-3);
		}

		GraphCollection gc = null;
		try {
			gc = TriGPlusReader.readFile(inputGraph, true);
		}
		catch (Exception e) {
			System.err.println("Input file does not contain valid graphs.");
			// e.printStackTrace();
			System.exit(-3);
		}

		try {
			signer.signGraph(keyPair, gc, outputGraph, config);
		}
		catch (Exception e) {
			System.err.println("Signing operation failed.");
			// e.printStackTrace();
			System.exit(-4);
		}

		System.out.println("Input graph was successfully signed.");
	}

	void signGraph(KeyPair keyPair, GraphCollection inputGraph,
			String outputGraph, SignatureAlgorithmInterface config)
			throws Exception {

		config.canonicalize(inputGraph);
		config.postCanonicalize(inputGraph);
		config.hash(inputGraph, envHashAlgorithm);
		config.postHash(inputGraph);
		config.sign(inputGraph, keyPair.getPrivate(), "\"cert\"");
		config.assemble(inputGraph, "_:sigGraph");

		TriGPlusWriter.writeFile(inputGraph, outputGraph);
	}
}
