package gaddam1987.github.auth.config.util;

import gaddam1987.github.auth.config.Message;
import gaddam1987.github.auth.config.RSAPubKeyReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64;

@Component
public class RSASHA1SignatureUtil {
    private static final String SIGNATURE_NAME = "SHA256withRSA";

    private final RSAPubKeyReader rsaKeyReader;

    @Autowired
    public RSASHA1SignatureUtil(RSAPubKeyReader rsaKeyReader) {
        this.rsaKeyReader = rsaKeyReader;
    }

    /**
     * @param message Output content for message
     * @return The signature, digest and actual message.
     * @throws UnsupportedOperationException If there is no private key.
     * @throws ResponseSigningException      If unable to sign the response.
     */
    public Message sign(String message) {
        PrivateKey privateKey = rsaKeyReader.getPrivateKey();
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

        } catch (Exception e) {
            throw new ResponseSigningException("Unable to sign the response", e);
        }
    }

    /**
     * @param inputMessage Domain object which holds message, digest, signature
     * @throws SignatureVerifyingException   If the signature is invalid for the specified base string. or if we face any error while
     *                                       verifying
     * @throws UnsupportedOperationException If there is no public key.
     */
    public void verify(Message inputMessage) throws UnsupportedEncodingException {
        PublicKey publicKey = rsaKeyReader.getPublicKey();
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
        } catch (Exception e) {
            throw new SignatureVerifyingException("Exception while verifying signature", e);
        }
    }

    private void verifyContentDigest(String message, byte[] messageDigest) throws Exception {
        if (!Arrays.equals(sha256Digest(message), messageDigest)) {
            throw new SignatureVerifyingException("Content digest mismatched");
        }
    }

    private byte[] sha256Digest(String message) throws Exception {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(message.getBytes());
        return instance.digest();
    }
}
