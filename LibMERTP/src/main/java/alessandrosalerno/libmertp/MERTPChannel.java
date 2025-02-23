package alessandrosalerno.libmertp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PublicKey;

public class MERTPChannel {
    private final KeyPair myKeys;
    private final PublicKey otherPublicKey;
    private final MERTPSymAESKey aes;
    private final InputStream inputStream;
    private final OutputStream outputStream;

    public MERTPChannel(KeyPair myKeys, PublicKey otherPublicKey, MERTPSymAESKey aes, InputStream inputStream, OutputStream outputStream) {
        this.myKeys = myKeys;
        this.otherPublicKey = otherPublicKey;
        this.aes = aes;
        this.inputStream = inputStream;
        this.outputStream = outputStream;
    }

    public void writeMessage(MERTPMessage message) throws IOException {
        byte[] msgBytes = LibMERTP.prepareMessage(message, this.aes);
        this.outputStream.write(msgBytes);
    }

    public MERTPMessage readMessage() throws IOException {
        byte[] encryptedBytes = LibMERTP.Network.read(this.inputStream);
        byte[] encodedBytes = LibMERTP.Crypto.aesDecryptBytes(encryptedBytes, this.aes.key(), this.aes.iv());
        return LibMERTP.parseMessage(encodedBytes);
    }

    public void close() throws IOException {
        this.writeMessage(LibMERTP.newDisconnectMsg());
    }
}
