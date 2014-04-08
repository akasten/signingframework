package de.uni_koblenz.aggrimm.icp.crypto.sign.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyPair {

	private static String algorithmName = "RSA";

	private KeyPair keyPair;

	public RSAKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithmName);
		keyGen.initialize(keySize);

		this.keyPair = keyGen.generateKeyPair();
	}

	public RSAKeyPair(String privateKeyFileName, String publicKeyFileName)
			throws IOException {
		
		File privateKeyFile = new File(privateKeyFileName);
		File publicKeyFile = new File(publicKeyFileName);

		FileInputStream fis = null;
		byte[] keyBytes = null;
		KeyFactory keyFactory = null;
		PrivateKey privateKey = null;
		PublicKey publicKey = null;

		try {
			fis = new FileInputStream(privateKeyFile);
			keyBytes = new byte[(int) privateKeyFile.length()];
			fis.read(keyBytes);
		}
		finally {
			fis.close();
		}

		try {
			keyFactory = KeyFactory.getInstance(algorithmName);
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					keyBytes);
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		catch (InvalidKeySpecException e) {
			throw new IOException(e);
		}

		try {
			fis = new FileInputStream(publicKeyFile);
			keyBytes = new byte[(int) publicKeyFile.length()];
			fis.read(keyBytes);
		}
		finally {
			fis.close();
		}

		try {
			keyFactory = KeyFactory.getInstance(algorithmName);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
			publicKey = keyFactory.generatePublic(publicKeySpec);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		catch (InvalidKeySpecException e) {
			throw new IOException(e);
		}

		this.keyPair = new KeyPair(publicKey, privateKey);
	}
	
	public KeyPair getKeyPair() {
		return this.keyPair;
	}

	public PrivateKey getPrivateKey() {
		return this.keyPair.getPrivate();
	}

	public PublicKey getPublicKey() {
		return this.keyPair.getPublic();
	}

	public void writePrivateKey(String fileName) throws IOException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(this.keyPair
				.getPrivate().getEncoded());

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(fileName);
			fos.write(keySpec.getEncoded());
		}
		catch (FileNotFoundException e) {
			throw new IOException(e);
		}
		finally {
			fos.close();
		}
	}

	public void writePublicKey(String fileName) throws IOException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(this.keyPair
				.getPublic().getEncoded());

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(fileName);
			fos.write(keySpec.getEncoded());
		}
		finally {
			fos.close();
		}
	}
}
