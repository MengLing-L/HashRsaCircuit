/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators.rsahash;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.rsa.RSAEncryptionV1_5_Gadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.generators.rsa.RSAUtil;


// a demo for RSA Encryption PKCS #1, V1.5
public class RSAEncryptionHashCircuitGenerator extends CircuitGenerator {

	private int rsaKeyLength;
	private int plainTextLength;
	private Wire[] inputMessage;
	private Wire[] randomness;
	private Wire[] cipherText;
	private LongElement rsaModulus;

	private SHA256Gadget sha2Gadget;
	private RSAEncryptionV1_5_Gadget rsaEncryptionV1_5_Gadget;

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
		randomness = createProverWitnessWireArray(RSAEncryptionV1_5_Gadget
				.getExpectedRandomnessLength(rsaKeyLength, plainTextLength));
		rsaEncryptionV1_5_Gadget = new RSAEncryptionV1_5_Gadget(rsaModulus, inputMessage,
				randomness, rsaKeyLength);
		
		// since randomness is a witness
		rsaEncryptionV1_5_Gadget.checkRandomnessCompliance();
		Wire[] cipherTextInBytes = rsaEncryptionV1_5_Gadget.getOutputWires(); // in bytes
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
			BigInteger modulus = ((RSAPublicKey) pubKey).getModulus();

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			evaluator.setWireValue(this.rsaModulus, modulus,
					LongElement.CHUNK_BITWIDTH);

			Key privKey = pair.getPrivate();

			cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
			byte[] cipherText = cipher.doFinal(msg.getBytes());
//			System.out.println("ciphertext : " + new String(cipherText));
			byte[] cipherTextPadded = new byte[cipherText.length + 1];
			System.arraycopy(cipherText, 0, cipherTextPadded, 1, cipherText.length);
			cipherTextPadded[0] = 0;

			byte[][] result = RSAUtil.extractRSARandomness1_5(cipherText,
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
				evaluator.setWireValue(randomness[i], (sampleRandomness[i]+256)%256);
			}

		} catch (Exception e) {
			System.err
					.println("Error while generating sample input for circuit");
			e.printStackTrace();
		}

	}

	public static void main(String[] args) throws Exception {
		int keyLength = 1024;
		int msgLength = 3;
		long startTime=System.currentTimeMillis();
		RSAEncryptionHashCircuitGenerator generator = new RSAEncryptionHashCircuitGenerator(
				"rsahash" + keyLength + "_hashencryption", keyLength, msgLength);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
		long endTime=System.currentTimeMillis();  
		System.out.println("Process time: "+(endTime-startTime)+"ms"); 
	}

}
