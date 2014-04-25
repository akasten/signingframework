package de.uni_koblenz.aggrimm.icp.crypto.sign.main;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Scanner;

import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.SignatureAlgorithmInterface;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.SignatureAlgorithmList;
import de.uni_koblenz.aggrimm.icp.crypto.sign.algorithm.SignatureVerifier;
import de.uni_koblenz.aggrimm.icp.crypto.sign.graph.GraphCollection;
import de.uni_koblenz.aggrimm.icp.crypto.sign.trigplus.TriGPlusReader;

public class Main {

	private static Scanner inReader;

	public static void main(String[] args) {

		if (args.length > 0) {
			Sign.main(args);
			return;
		}

		inReader = new Scanner(System.in);

		boolean running = true;

		while (running) {
			switch (getChoice("What do you want to do today?",
					" (1) Create a key pair\n" + " (2) Sign a graph\n"
							+ " (3) Verify a signature\n" + " (4) Quit", 4)) {
				case 1:
					createKey();
					break;
				case 2:
					signGraph();
					break;
				case 3:
					verifySignature();
					break;
				case 4:
					running = false;
					System.out.println("Thank you for using this application.");
					break;
			}
			System.out.println();
		}

		inReader.close();
	}

	/**
	 * Creates a key pair and asks for all necessary input data. The created key
	 * files are stored to disk.
	 */
	private static void createKey() {
		String keyPrefix = getStringValue("Please specify a filename prefix for the created key files:");
		RSAKeyPair keyPair = null;

		try {
			switch (getChoice("Chose the key size of the RSA key:",
					" (1) 2048 bit\n" + " (2) 3072 bit", 2)) {
				case 1:
					keyPair = new RSAKeyPair(2048);
					break;
				case 2:
					keyPair = new RSAKeyPair(3072);
					break;
			}

			keyPair.writePublicKey(keyPrefix + "_public.key");
			keyPair.writePrivateKey(keyPrefix + "_private.key");

			System.out
					.println("The key pair was created and output to the following files:");
			System.out.println("  Public key : " + keyPrefix + "_public.key");
			System.out.println("  Private key: " + keyPrefix + "_private.key");
		}
		catch (NoSuchAlgorithmException e) {
			System.err
					.println("An unexpected error occured. The key could not be created.");
		}
		catch (IOException e) {
			System.err
					.println("An unexpected error occured. The key files could not be created.");
		}
	}

	/**
	 * Signs a graph and asks for all necessary input data. The signed output
	 * graph is stored to disk.
	 */
	private static void signGraph() {
		Sign signer = new Sign();

		System.out
				.println("In order to sign a graph, you must first specicy some parameters.");

		String inputGraph = getStringValue("Please specify the filename of the graph to be signed:");
		GraphCollection gc = null;
		try {
			gc = TriGPlusReader.readFile(inputGraph, true);
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The specified input file does not contain a valid set of graphs.");
			return;
		}

		String outputGraph = getStringValue("Please specify the filename of the signed output graph:");

		RSAKeyPair keyPair = null;
		String skFileName = getStringValue("Please specify the filename of the private key file:");
		String pkFileName = getStringValue("Please specify the filename of the public key file:");
		try {
			keyPair = new RSAKeyPair(skFileName, pkFileName);
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The specified key files do not contain a valid key pair.");
			return;
		}

		SignatureAlgorithmInterface config = null;
		try {
			switch (getChoice(
					"Please specify the framework configuration to be used for signing the graph:",
					" (1) carroll-2003\n" + " (2) fisteus-2010\n"
							+ " (3) sayers-2004\n" + " (4) tummarello-2005", 4)) {
				case 1:
					config = SignatureAlgorithmList
							.getAlgorithm("carroll-2003");
					break;
				case 2:
					config = SignatureAlgorithmList
							.getAlgorithm("fisteus-2010");
					break;
				case 3:
					config = SignatureAlgorithmList.getAlgorithm("sayers-2004");
					break;
				case 4:
					config = SignatureAlgorithmList
							.getAlgorithm("tummarello-2005");
					break;
			}
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The specified configuration is not available.");
			return;
		}

		try {
			signer.signGraph(keyPair.getKeyPair(), gc, outputGraph, config);
			System.out
					.println("The input graphs were successfully signed. The result is stored in the file '"
							+ outputGraph + "'.");
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The graph could not be signed.");
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Verifies the signature of a signed graph.
	 */
	private static void verifySignature() {
		System.out
				.println("In order to sign a graph, you must first specicy some parameters.");

		String inputGraph = getStringValue("Please specify the filename of the signed graph:");
		GraphCollection gc = null;
		try {
			gc = TriGPlusReader.readFile(inputGraph, true);
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The specified input file does not contain a valid set of graphs.");
			return;
		}

		PublicKey publicKey = null;
		String pkFileName = getStringValue("Please specify the filename of the public key file:");
		try {
			publicKey = RSAKeyPair.loadPublicKey(pkFileName);
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The specified key files do not contain a valid public key.");
			return;
		}

		try {
			if (SignatureVerifier.verify(gc, publicKey)) {
				System.out.println("The signature is valid.");
			}
			else {
				System.out.println("The signature is invalid.");
			}
		}
		catch (Exception e) {
			System.err
					.println("An unexpected error occured. The graph could not be signed.");
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Returns a string value specified by the user.
	 * 
	 * @param questionString
	 *            The question printed to the user.
	 * @return The string value input by the user. The string contains at least
	 *         one character.
	 */
	private static String getStringValue(String questionString) {
		System.out.println(questionString);

		String prefix = null;

		while (prefix == null) {
			String input = inReader.nextLine();

			if (input.length() == 0)
				System.out
						.println("Invalid input. Please input at least one character:");
			else
				prefix = input;
		}

		return prefix;
	}

	/**
	 * Returns an integer value corresponding to a valid user choice.
	 * 
	 * @param questionString
	 *            The question printed to the user.
	 * @param optionString
	 *            The option string printed to the user. The string contains all
	 *            valid options.
	 * @param numberOfOptions
	 *            An integer value defining the maximum valid choice. The
	 *            minimum choice value is 1.
	 * @return The user's choice.
	 */
	private static int getChoice(String questionString, String optionString,
			int numberOfOptions) {
		System.out.println(questionString);
		System.out.println(optionString);

		int result = 0;

		while (result == 0) {
			String input = inReader.nextLine();

			try {
				result = Integer.parseInt(input);

				if (result <= 0 || result > numberOfOptions) {
					throw new Exception();
				}
			}
			catch (Exception e) {
				System.out
						.println("Invalid choice. Please chose one of the following options:");
				System.out.println(optionString);

				result = 0;
			}

		}

		return result;
	}

}
