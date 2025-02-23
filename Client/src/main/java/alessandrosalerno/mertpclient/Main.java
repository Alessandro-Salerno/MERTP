package alessandrosalerno.mertpclient;

import alessandrosalerno.libmertp.LibMERTP;
import alessandrosalerno.libmertp.MERTPChannel;
import alessandrosalerno.libmertp.MERTPMessage;
import alessandrosalerno.libmertp.MERTPServerHandshake;
import alessandrosalerno.libmertp.exceptions.MERTPMalformedHandshakeException;
import alessandrosalerno.libmertp.exceptions.MERTPServerAuthenticationException;
import alessandrosalerno.libmertp.exceptions.MERTPVersionMismatchException;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.Queue;

public class Main {
    public static Queue<String> readBuffer = new LinkedList<>();
    public static Terminal terminal;

    public static void exit(int code) {
        System.out.print("Press ENTER to exit");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        try {
            br.readLine();
        } catch (Exception ignored) {}
        finally {
            System.exit(code);
        }
    }

    public static void handlePrint(String payload, MERTPChannel channel) {
        System.out.print(payload);
    }

    public static void handleRead(MERTPMessage message, MERTPChannel channel) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        Console console = System.console();

        try {
            String input = "";
            if (LibMERTP.InputTypes.TEXT.equals(message.getHeader("Input-Type"))) {
                if (!readBuffer.isEmpty()) {
                    input = readBuffer.poll();
                    System.out.println(input);
                } else {
                    input = reader.readLine();
                }
            } else if (LibMERTP.InputTypes.PASSWORD.equals(message.getHeader("Input-Type"))) {
                input = new String(console.readPassword());
            }
            int terminalWidth = 0;
            int terminalHeight = 0;
            try {
                terminalWidth = terminal.getWidth();
                terminalHeight = terminal.getHeight();
            } catch (Exception ignored) {
                terminalWidth = 80;
                terminalHeight = 40;
            }
            MERTPMessage answer = LibMERTP.newAnswerMsg(input, terminalHeight, terminalWidth);
            channel.writeMessage(answer);
        } catch (Exception ignored) {}
    }

    public static void handleRedirect(MERTPMessage message, MERTPChannel channel) {

    }

    public static void handleBufferPush(String content) {
        readBuffer.add(content);
    }

    public static void handleDisconnect(MERTPMessage message, MERTPChannel channel) {

    }

    public static void handleMessage(MERTPMessage message, MERTPChannel channel) {
        switch (message.getMessageType()) {
            case LibMERTP.MessageTypes.PRINT -> handlePrint(message.getPayload(), channel);
            case LibMERTP.MessageTypes.READ -> handleRead(message, channel);
            case LibMERTP.MessageTypes.REDIRECT -> handleRedirect(message, channel);
            case LibMERTP.MessageTypes.BUFFER_PUSH -> handleBufferPush(message.getHeader("Content"));
            case LibMERTP.MessageTypes.DISCONNECT -> handleDisconnect(message, channel);
        }
    }

    public static void main(String[] args) throws IOException {
        terminal = TerminalBuilder.terminal();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Client for the Minimal Encrypted Remote Terminal Protocol");
        System.out.println("Copyright (C) 2025 Alessandro Salerno");
        System.out.println();

        System.out.print("MERTP Server address: ");
        String address = reader.readLine();
        System.out.print("MERTP Server port: ");
        int port = Integer.parseInt(reader.readLine());
        System.out.println();

        System.out.println("Connecting to the server...");

        try (Socket socket = new Socket(address, port)) {
            final InputStream is = socket.getInputStream();
            final OutputStream os = socket.getOutputStream();
            final KeyPair clientKeys = LibMERTP.Crypto.rsaNewKeyPair();

            System.out.println("Establishing MERTP channel...");
            LibMERTP.writeClientHandshake(os, clientKeys.getPublic());

            MERTPServerHandshake server = null;

            try {
                server = LibMERTP.readServerHandshake(is, clientKeys);
            } catch (MERTPVersionMismatchException | MERTPMalformedHandshakeException |
                     MERTPServerAuthenticationException e) {
                System.out.println(e.getMessage());
                exit(-1);
            }

            final MERTPChannel channel = new MERTPChannel(clientKeys, server.serverPublicKey(), server.aesKey(), is, os);
            System.out.println("Connected to " + server.serverName() + ". Control of CLI I/O operations has been handed " +
                                "over to the server.\n\n");

            LOOP: while (true) {
                MERTPMessage message = channel.readMessage();
                handleMessage(message, channel);
            }
        } catch (IOException e) {
            System.out.println("Connection lost");
            exit(-1);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Encryption error");
            exit(-1);
        }
    }
}