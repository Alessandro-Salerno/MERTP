package alessandrosalerno.libmertp;

import alessandrosalerno.libmertp.exceptions.MERTPMalformedHandshakeException;
import alessandrosalerno.libmertp.exceptions.MERTPServerAuthenticationException;
import alessandrosalerno.libmertp.exceptions.MERTPVersionMismatchException;
import org.apache.commons.text.StringEscapeUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class LibMERTP {
    public static class MessageTypes {
        public static final String PRINT = "PRINT";
        public static final String READ = "READ";
        public static final String ANSWER = "ANSWER";
        public static final String REDIRECT = "REDIRECT";
        public static final String BUFFER_PUSH = "BUFFER PUSH";
        public static final String DISCONNECT = "DISCONNECT";
    }

    public static class InputTypes {
        public static final String TEXT = "Text";
        public static final String PASSWORD = "Password";
    }

    public static class Crypto {
        public static PublicKey rsaPublicKeyFromBytes(byte[] encodedKey)
                throws NoSuchAlgorithmException, InvalidKeySpecException {
            X509EncodedKeySpec kSpec = new X509EncodedKeySpec(encodedKey);
            return KeyFactory.getInstance("RSA").generatePublic(kSpec);
        }

        public static byte[] rsaEncryptBytes(byte[] message, Key key) {
            try {
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] rsaDecryptBytes(byte[] message, Key key) {
            try {
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] aesEncryptBytes(byte[] message, SecretKey key, IvParameterSpec iv) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] aesDecryptBytes(byte[] message, SecretKey key, IvParameterSpec iv) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static KeyPair rsaNewKeyPair() {
            try {
                SecureRandom secureRandom = new SecureRandom();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(4096, secureRandom);
                return keyPairGenerator.generateKeyPair();
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                return null;
            }
        }

        public static MERTPSymAESKey aesNewKey() {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256);
                SecretKey key = keyGenerator.generateKey();
                byte[] ivBytes = new byte[16];
                new SecureRandom().nextBytes(ivBytes);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                return new MERTPSymAESKey(key, iv);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class Network {
        public static byte[] wrap(byte[] message) {
            ByteBuffer bytes = ByteBuffer.allocate(4 + message.length);
            bytes.putInt(message.length);
            bytes.put(message);
            return bytes.array();
        }

        public static byte[] read(InputStream inputStream) throws IOException {
            byte[] lengthBytes = inputStream.readNBytes(4);
            int length = ByteBuffer.wrap(lengthBytes).getInt();
            return inputStream.readNBytes(length);
        }
    }

    public static final short MERTP_VERSION = 010000;

    public static MERTPMessage newPrintMsg(String payload) {
        return new MERTPMessage(MessageTypes.PRINT, payload);
    }

    public static MERTPMessage newReadMsg(String inputType) {
        MERTPMessage msg = new MERTPMessage(MessageTypes.READ);
        msg.addHeader("Input-Type", inputType);
        return msg;
    }

    public static MERTPMessage newAnswerMsg(String content, int rows, int cols) {
        MERTPMessage msg = new MERTPMessage(MessageTypes.ANSWER);
        msg.addHeader("Content", content);
        msg.addHeader("Terminal-Rows", rows);
        msg.addHeader("Terminal-Columns", cols);
        return msg;
    }

    public static MERTPMessage newRedirectMsg(String serverAddress, int serverPort) {
        MERTPMessage msg = new MERTPMessage(MessageTypes.REDIRECT);
        msg.addHeader("Server-Address", serverAddress);
        msg.addHeader("Server-Port", serverPort);
        return msg;
    }

    public static MERTPMessage newBufferPushMsg(String content) {
        MERTPMessage msg = new MERTPMessage(MessageTypes.BUFFER_PUSH);
        msg.addHeader("Content", content);
        return msg;
    }

    public static MERTPMessage newDisconnectMsg() {
        return new MERTPMessage(MessageTypes.DISCONNECT);
    }

    public static PublicKey readClientHandshake(InputStream is) throws MERTPMalformedHandshakeException,
            MERTPVersionMismatchException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] prefix = is.readNBytes(5);

        if (!"MERTP".equals(new String(prefix, StandardCharsets.UTF_8))) {
            throw new MERTPMalformedHandshakeException();
        }

        byte[] versionBytes = is.readNBytes(2);
        ByteBuffer versionBuffer = ByteBuffer.wrap(versionBytes);
        short otherVersion = versionBuffer.getShort();

        if (LibMERTP.MERTP_VERSION != otherVersion) {
            throw new MERTPVersionMismatchException(otherVersion);
        }

        byte[] keyLengthBytes = is.readNBytes(4);
        int keyLength = ByteBuffer.wrap(keyLengthBytes).getInt();

        byte[] clientPublicKeyBytes = is.readNBytes(keyLength);
        return Crypto.rsaPublicKeyFromBytes(clientPublicKeyBytes);
    }

    public static MERTPServerHandshake readServerHandshake(InputStream is, KeyPair clientKeys) throws MERTPMalformedHandshakeException, MERTPVersionMismatchException, IOException, MERTPServerAuthenticationException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] prefix = is.readNBytes(5);

        if (!"MERTP".equals(new String(prefix, StandardCharsets.UTF_8))) {
            throw new MERTPMalformedHandshakeException();
        }

        byte[] versionBytes = is.readNBytes(2);
        ByteBuffer versionBuffer = ByteBuffer.wrap(versionBytes);
        short otherVersion = versionBuffer.getShort();

        if (LibMERTP.MERTP_VERSION != otherVersion) {
            throw new MERTPVersionMismatchException(otherVersion);
        }

        byte[] nameLengthBytes = is.readNBytes(4);
        int nameLength = ByteBuffer.wrap(nameLengthBytes).getInt();
        String serverName = new String(is.readNBytes(nameLength), StandardCharsets.UTF_8);

//        byte[] signLengthBytes = is.readNBytes(4);
//        int signLength = ByteBuffer.wrap(signLengthBytes).getInt();
//        byte[] signature = is.readNBytes(signLength);
//        byte[] decryptedSign = Crypto.rsaDecryptBytes(signature, clientKeys.getPrivate());
//
//        if (0 != Arrays.compare(decryptedSign, clientKeys.getPublic().getEncoded())) {
//            throw new MERTPServerAuthenticationException();
//        }

        byte[] serverKeyLengthBytes = is.readNBytes(4);
        int serverKeyLength = ByteBuffer.wrap(serverKeyLengthBytes).getInt();
        byte[] serverKeyBytes = is.readNBytes(serverKeyLength);
        PublicKey serverPublicKey = Crypto.rsaPublicKeyFromBytes(serverKeyBytes);

        byte[] encryptedAesKey = is.readNBytes(512);
        byte[] encryptedAesIv = is.readNBytes(512);
        byte[] encodedAesKey = Crypto.rsaDecryptBytes(encryptedAesKey, clientKeys.getPrivate());
        byte[] encodedAesIv = Crypto.rsaDecryptBytes(encryptedAesIv, clientKeys.getPrivate());

        SecretKey aesKey = new SecretKeySpec(encodedAesKey, "AES");
        IvParameterSpec aesIv = new IvParameterSpec(encodedAesIv);
        MERTPSymAESKey aes = new MERTPSymAESKey(aesKey, aesIv);

        return new MERTPServerHandshake(serverName, serverPublicKey, aes);
    }

    public static void writeClientHandshake(OutputStream os, PublicKey clientPublicKey) throws IOException {
        byte[] encodedKey = clientPublicKey.getEncoded();
        ByteBuffer bytes = ByteBuffer.allocate(5 + 2 + 4 + encodedKey.length);
        bytes.put("MERTP".getBytes(StandardCharsets.UTF_8));
        bytes.putShort(LibMERTP.MERTP_VERSION);
        bytes.putInt(encodedKey.length);
        bytes.put(encodedKey);
        os.write(bytes.array());
    }

    public static void writeServerHandshake(OutputStream os, String serverName, PublicKey clientPublicKey,
                                            KeyPair serverKeys, MERTPSymAESKey aesKey) throws IOException {
        byte[] encodedClientKey = clientPublicKey.getEncoded();
        byte[] encodedServerName = serverName.getBytes(StandardCharsets.UTF_8);
//        byte[] signature = Crypto.rsaEncryptBytes(encodedClientKey, serverKeys.getPrivate());
        byte[] encodedServerKey = serverKeys.getPublic().getEncoded();
        byte[] encodedAesKey = aesKey.key().getEncoded();
        byte[] encodedAesIv = aesKey.iv().getIV();
        byte[] encryptedAesKey = Crypto.rsaEncryptBytes(encodedAesKey, clientPublicKey);
        byte[] encryptedAesIv = Crypto.rsaEncryptBytes(encodedAesIv, clientPublicKey);

        ByteBuffer bytes = ByteBuffer.allocate(5 + 2 + 4 + encodedServerName.length + /* 4 + signature.length */
                                                + 4 + encodedServerKey.length  + encryptedAesKey.length
                                                + encryptedAesIv.length);

        bytes.put("MERTP".getBytes(StandardCharsets.UTF_8));
        bytes.putShort(LibMERTP.MERTP_VERSION);
        bytes.putInt(encodedServerName.length);
        bytes.put(encodedServerName);
//        bytes.putInt(signature.length);
//        bytes.put(signature);
        bytes.putInt(encodedServerKey.length);
        bytes.put(encodedServerKey);
        bytes.put(encryptedAesKey);
        bytes.put(encryptedAesIv);

        os.write(bytes.array());
    }

    public static MERTPMessage parseMessage(byte[] message) {
        String msg = new String(message, StandardCharsets.UTF_8);
        String[] lines = msg.split("\n");

        MERTPMessage finalMsg = new MERTPMessage(lines[0]);
        int bodyIndex = 1 + finalMsg.getMessageType().length();

        for (int i =  1; i < lines.length && !lines[i].isEmpty(); i++) {
            String[] values = lines[i].split(":");
            String key = values[0];
            StringBuilder valueBuild = new StringBuilder();
            for (String v : Arrays.copyOfRange(values, 1, values.length)) {
                valueBuild.append(v);
            }
            String value = StringEscapeUtils.unescapeJava(valueBuild.toString());
            finalMsg.addHeader(key, value);
            bodyIndex += lines[i].length();
        }

        if (bodyIndex < msg.length()) {
            String body = msg.substring(bodyIndex + 1);
            finalMsg.setPayload(body);
        }

        return finalMsg;
    }

    public static byte[] prepareMessage(MERTPMessage message, MERTPSymAESKey aes) {
        String request = message.toProtocolMessage();
        byte[] requestBytes = request.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedRequest = LibMERTP.Crypto.aesEncryptBytes(requestBytes, aes.key(), aes.iv());
        return LibMERTP.Network.wrap(encryptedRequest);
    }
}
