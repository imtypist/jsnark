package examples.generators.rsa;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
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
import examples.gadgets.rsa.RSASigVerificationV1_5_Gadget;
import examples.gadgets.hash.SHA256Gadget;

public class VANETCircuitGenerator extends CircuitGenerator{
    private int rsaKeyLength;
    private int plainTextLength;
    private Wire[] inputMessage;
    private Wire[] randomness;
    private Wire[] cipherText;
    private Wire[] publicKey;
    private LongElement raModulus; // mpk, (modulus||exponent) is the public key, here the exponent always is 65537, i.e., 0x10001.
    private LongElement rsaModulus; // pk
    private LongElement signature;

    private RSAEncryptionV1_5_Gadget rsaEncryptionV1_5_Gadget;
    private SHA256Gadget sha2Gadget;
    private RSASigVerificationV1_5_Gadget rsaSigVerificationV1_5_Gadget;

    public VANETCircuitGenerator(String circuitName, int rsaKeyLength,
                                         int plainTextLength) {
        super(circuitName);
        this.rsaKeyLength = rsaKeyLength;
        this.plainTextLength = plainTextLength;
        // constraints on the plaintext length will be checked by the gadget
    }

    @Override
    protected void buildCircuit() {
        /**
         * here, inputMessage and mpk are common knowledge, pk, sk, cert are private witnesses.
         */

        // verify the signature
        publicKey = createProverWitnessWireArray(rsaKeyLength/4); // private witness, rsaModulus
        for(int i = 0; i < rsaKeyLength/4;i++){ // in bytes
            publicKey[i].restrictBitLength(8);
        }
        sha2Gadget = new SHA256Gadget(publicKey, 8, publicKey.length, false, true);
        Wire[] digest = sha2Gadget.getOutputWires();
        raModulus = createLongElementInput(rsaKeyLength); // common knowledge

        // since the signature is provided as a witness, verify some properties about it
        signature = createLongElementProverWitness(rsaKeyLength); // private witness
        signature.restrictBitwidth();
        signature.assertLessThan(raModulus); // might not be really necessary in that case

        // verify
        rsaSigVerificationV1_5_Gadget = new RSASigVerificationV1_5_Gadget(
                raModulus, digest, signature, rsaKeyLength);
        makeOutput(rsaSigVerificationV1_5_Gadget.getOutputWires()[0],
                "Is Signature valid?");

        // encryption
        inputMessage = createInputWireArray(plainTextLength); // in bytes

        randomness = createProverWitnessWireArray(RSAEncryptionV1_5_Gadget.getExpectedRandomnessLength(rsaKeyLength, plainTextLength)); // private witness, similar to private key
        // constraints on the randomness vector are checked later.


        /**
         * Since an RSA modulus take many wires to present, it could increase
         * the size of verification key if we divide it into very small chunks,
         * e.g. 32-bits (which happens by default in this version to minimize
         * the number of gates later in the circuit). In case the verification
         * key size is important, e.g. going to be stored in a smart contract, a
         * possible workaround could be by either assuming the largest possible
         * bitwidths for the chunks, and then converting them into smaller
         * chunks, or let the prover provide the key as a witness to the
         * circuit, and compute its hash, which will be part of the statement.
         * This way of doing this increases the number of gates a bit, but
         * reduces the VK size when crucial.
         *
         **/

        rsaModulus = createLongElementProverWitness(rsaKeyLength); // private witness, public key
        rsaModulus.restrictBitwidth();

        rsaEncryptionV1_5_Gadget = new RSAEncryptionV1_5_Gadget(rsaModulus, inputMessage, randomness, rsaKeyLength);

        // since the randomness vector is a witness in this example, verify any needed constraints
        rsaEncryptionV1_5_Gadget.checkRandomnessCompliance();

        Wire[] cipherTextInBytes = rsaEncryptionV1_5_Gadget.getOutputWires(); // in bytes

        // do some grouping to reduce VK Size
        cipherText = new WireArray(cipherTextInBytes).packWordsIntoLargerWords(8, 30);
        makeOutputArray(cipherText, "Output cipher text");

    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        // simulate input message, e.g., pseudo random address || GPS data
        String msg = "0xd91c747b4a76B8013Aa336Cbc52FD95a7a9BD3D9$GPRMC,092927.000,A,2235.9058,N,11400.0518,E,0.000,74.11,151216,,D*49";
        for (int i = 0; i < inputMessage.length; i++) {

            evaluator.setWireValue(inputMessage[i], msg.charAt(i));
            // msg = msg + (char) ('a' + i);
        }
        System.out.println("PlainText:" + msg);

        try {
            // generate (mpk, msk) for RA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(rsaKeyLength, new SecureRandom());
            KeyPair raKeyPair = keyGen.generateKeyPair();

            // generate (pk, sk) for vehicle
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(rsaKeyLength, random);
            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            BigInteger modulus = ((RSAPublicKey) pubKey).getModulus();

            // CertGen(msk, pk) -> cert
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(raKeyPair.getPrivate());
            byte[] message = modulus.toString(16).getBytes();
            // publicKey wire array
            for (int i = 0; i < message.length; i++){
                evaluator.setWireValue(publicKey[i], message[i]);
            }
            signature.update(message);
            byte[] sigBytes = signature.sign();
            byte[] signaturePadded = new byte[sigBytes.length + 1];
            System.arraycopy(sigBytes, 0, signaturePadded, 1, sigBytes.length);
            signaturePadded[0] = 0;
            BigInteger raModulus = ((RSAPublicKey) raKeyPair.getPublic()).getModulus();
            BigInteger sig = new BigInteger(signaturePadded);

            evaluator.setWireValue(this.raModulus, raModulus, LongElement.CHUNK_BITWIDTH);
            evaluator.setWireValue(this.signature, sig, LongElement.CHUNK_BITWIDTH);

            // to make sure that the implementation is working fine,
            // encrypt with the underlying java implementation for RSA
            // Encryption in a sample run,
            // extract the randomness (after decryption manually), then run the
            // circuit with the extracted randomness

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            evaluator.setWireValue(this.rsaModulus, modulus, LongElement.CHUNK_BITWIDTH);
            Key privKey = pair.getPrivate();
            cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
            byte[] cipherText = cipher.doFinal(msg.getBytes());
//			System.out.println("ciphertext : " + new String(cipherText));
            byte[] cipherTextPadded = new byte[cipherText.length + 1];
            System.arraycopy(cipherText, 0, cipherTextPadded, 1, cipherText.length);
            cipherTextPadded[0] = 0;

            byte[][] result = RSAUtil.extractRSARandomness1_5(cipherText, (RSAPrivateKey) privKey);
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
        int keyLength = 2048;
        int msgLength = 111;
        VANETCircuitGenerator generator = new VANETCircuitGenerator(
                "vanet_rsa" + keyLength, keyLength, msgLength);
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }
}
