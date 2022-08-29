/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators.rsahash;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.rsa.RSAEncryptionOAEPGadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.generators.rsa.RSAUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


// a demo for RSA Encryption PKCS #1, V1.5
public class RSAEncryptionHashCircuitGenerator extends CircuitGenerator {

	private int rsaKeyLength;
	private int plainTextLength;
	private Wire[] inputMessage;
	private Wire[] seed;
	private Wire[] cipherText;
	private LongElement rsaModulus;

	private SHA256Gadget sha2Gadget;
	private RSAEncryptionOAEPGadget rsaEncryptionOAEPGadget;


	public RSAEncryptionHashCircuitGenerator(String circuitName, int rsaKeyLength,
			int plainTextLength) {
		super(circuitName);
		this.rsaKeyLength = rsaKeyLength;
		this.plainTextLength = plainTextLength;
		// constraints on the plaintext length will be checked by the gadget
	}

	@Override
	protected void buildCircuit() {
		inputMessage = createProverWitnessWireArray(plainTextLength); // in bytes
		for(int i = 0; i < plainTextLength;i++){
			inputMessage[i].restrictBitLength(8);
		}
		
		rsaModulus = createLongElementInput(rsaKeyLength);
		seed = createProverWitnessWireArray(RSAEncryptionOAEPGadget.SHA256_DIGEST_LENGTH);
		rsaEncryptionOAEPGadget = new RSAEncryptionOAEPGadget(
							rsaModulus, inputMessage, seed, rsaKeyLength);
		
		// since randomness is a witness
		rsaEncryptionOAEPGadget.checkSeedCompliance();
		Wire[] cipherTextInBytes = rsaEncryptionOAEPGadget
							.getOutputWires(); // in bytes
		cipherText = new WireArray(cipherTextInBytes).packWordsIntoLargerWords(8, 8);
		System.out.println(cipherText.length);


		Wire[] digest = new SHA256Gadget(inputMessage, 8, plainTextLength, false, true, "").getOutputWires();
		
		System.out.println(digest.length);
		Wire[] hashCipherTextInBytes = new Wire[cipherText.length + digest.length];
		System.arraycopy(cipherText, 0, hashCipherTextInBytes, 0, cipherText.length);
		System.arraycopy(digest, 0, hashCipherTextInBytes, cipherText.length, digest.length);
		//Wire[] hashCipherTextInBytes = new WireArray(cipherTextInBytes).addWireArray(new WireArray(msgHashBytes), msgHashBytes.length).getBits(32).packBitsIntoWords(8);
		System.out.println(hashCipherTextInBytes.length);
		// group every 8 bytes together
		makeOutputArray(hashCipherTextInBytes,
				"Output hash and cipher text");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {

		String msg = "";
		for (int i = 0; i < inputMessage.length; i++) {

			evaluator.setWireValue(inputMessage[i], (int) ('a' + i));
			msg = msg + (char) ('a' + i);
		}
		System.out.println("PlainText:" + msg);

		try {

			// to make sure that the implementation is working fine,
			// encrypt with the underlying java implementation for RSA
			// Encryption in a sample run,
			// extract the randomness (after decryption manually), then run the
			// circuit with the extracted randomness

			SecureRandom random = new SecureRandom();
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(rsaKeyLength, random);
			KeyPair pair = generator.generateKeyPair();
			Key pubKey = pair.getPublic();
			BigInteger rsaModulusValue = ((RSAPublicKey) pubKey).getModulus();

			Security.addProvider(new BouncyCastleProvider());
					Cipher cipher = Cipher.getInstance(
								"RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");

					evaluator
							.setWireValue(this.rsaModulus, rsaModulusValue,
										LongElement.CHUNK_BITWIDTH);

					Key privKey = pair.getPrivate();

			cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

			byte[] cipherText = cipher.doFinal(msg.getBytes());
//			System.out.println("ciphertext : " + new String(cipherText));
			byte[] cipherTextPadded = new byte[cipherText.length + 1];
			System.arraycopy(cipherText, 0, cipherTextPadded, 1, cipherText.length);
			cipherTextPadded[0] = 0;

			byte[][] result = RSAUtil.extractRSAOAEPSeed(cipherText,
					(RSAPrivateKey) privKey);
			// result[0] contains the plaintext (after decryption)
			// result[1] contains the randomness

			boolean check = Arrays.equals(result[0], msg.getBytes());
			if (!check) {
				throw new RuntimeException(
						"Randomness Extraction did not decrypt right");
			}

			byte[] sampleRandomness = result[1];
			for (int i = 0; i < sampleRandomness.length; i++) {
				evaluator.setWireValue(seed[i], (sampleRandomness[i]+256)%256);
			}

		} catch (Exception e) {
			System.err
					.println("Error while generating sample input for circuit");
			e.printStackTrace();
		}

	}

	public static void main(String[] args) throws Exception {
		int keyLength = 2048;
		int msgLength = 30;
		long startTime=System.currentTimeMillis();
		RSAEncryptionHashCircuitGenerator generator = new RSAEncryptionHashCircuitGenerator(
				"rsa_oaep_hash" + keyLength + "_hashencryption", keyLength, msgLength);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
		long endTime=System.currentTimeMillis();  
		System.out.println("Process time: "+(endTime-startTime)+"ms"); 
	}

}
