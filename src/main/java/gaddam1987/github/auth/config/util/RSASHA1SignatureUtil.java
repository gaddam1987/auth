package gaddam1987.github.auth.config.util;

import gaddam1987.github.auth.config.Message;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64;

@Component
public class RSASHA1SignatureUtil {
    public static final String SIGNATURE_NAME = "SHA256withRSA";


    /**
     * @param message Output content for message
     * @return The signature, digest and actual message.
     * @throws UnsupportedOperationException If there is no private key.
     */
    public Message sign(String message, PrivateKey privateKey) {
        if (privateKey == null) {
            throw new UnsupportedOperationException("Cannot sign the base string: no private key supplied.");
        }

        try {
            Signature signer = Signature.getInstance(SIGNATURE_NAME);
            signer.initSign(privateKey);
            byte[] contentDigest = sha256Digest(message);
            signer.update(contentDigest);
            byte[] signatureBytes = signer.sign();


            return new Message(message,
                    new String(encodeBase64(contentDigest), "UTF-8"),
                    new String(encodeBase64(signatureBytes), "UTF-8"));

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @param inputMessage Domain object which holds message, digest, signature
     * @throws UnsupportedEncodingException  If the signature is invalid for the specified base string.
     * @throws UnsupportedOperationException If there is no public key.
     */
    public void verify(Message inputMessage, PublicKey publicKey) throws UnsupportedEncodingException {
        if (publicKey == null) {
            throw new UnsupportedOperationException("A public key must be provided to verify signatures.");
        }

        try {
            byte[] messageDigest = decodeBase64(inputMessage.getDigest());

            verifyContentDigest(inputMessage.getMessage(), messageDigest);

            byte[] signatureBytes = decodeBase64(inputMessage.getSignature());

            Signature verifier = Signature.getInstance(SIGNATURE_NAME);

            verifier.initVerify(publicKey);

            verifier.update(messageDigest);

            if (!verifier.verify(signatureBytes)) {
                throw new SignatureVerifyingException("Invalid signature");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    private void verifyContentDigest(String message, byte[] messageDigest) throws NoSuchAlgorithmException {
        if (!Arrays.equals(sha256Digest(message), messageDigest)) {
            throw new SignatureVerifyingException("Content digest mismatched");
        }
    }

    public byte[] sha256Digest(String message) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(message.getBytes());
        return instance.digest();
    }
}
