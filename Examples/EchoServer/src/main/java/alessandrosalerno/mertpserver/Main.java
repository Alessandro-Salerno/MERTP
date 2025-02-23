package alessandrosalerno.mertpserver;

import alessandrosalerno.libmertp.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.PublicKey;

public class Main {
    public static void main(String[] args) {
        LOOP: while (true) {
            try (ServerSocket serverSocket = new ServerSocket(8000)) {
                final Socket socket = serverSocket.accept();
                final InputStream is = socket.getInputStream();
                final OutputStream os = socket.getOutputStream();

                final PublicKey clientKey = LibMERTP.readClientHandshake(is);

                final KeyPair serverKeys = LibMERTP.Crypto.rsaNewKeyPair();
                final MERTPSymAESKey aes = LibMERTP.Crypto.aesNewKey();
                LibMERTP.writeServerHandshake(os, "TEST", clientKey, serverKeys, aes);

                final MERTPChannel channel = new MERTPChannel(serverKeys, clientKey, aes, is, os);

                new Thread(() -> {
                    try {
                        channel.writeMessage(LibMERTP.newBufferPushMsg("This message was pushed onto the read buffer by the server!"));

                        LOOP2: while (true) {
                            MERTPMessage question = LibMERTP.newReadMsg(LibMERTP.InputTypes.TEXT);
                            channel.writeMessage(LibMERTP.newPrintMsg("(You) "));
                            channel.writeMessage(question);

                            MERTPMessage answer = channel.readMessage();
                            if (answer.isOfType(LibMERTP.MessageTypes.ANSWER)) {
                                String content = answer.getHeader("Content");
                                String response = "(Server) " + content + "\n";
                                MERTPMessage reply = LibMERTP.newPrintMsg(response);
                                channel.writeMessage(reply);
                            }
                        }
                    } catch (SocketException e) {
                        System.out.println("Client disconnected");
                        return;
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                }).start();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}