package alessandrosalerno.libmertp.exceptions;

public class MERTPMalformedHandshakeException extends Exception {
    public MERTPMalformedHandshakeException(int got, int expected) {
        super("Got handshake message of length " + got + ", expected one of length " + expected);
    }

    public MERTPMalformedHandshakeException() {
        super("Handshake missing MERTP prefix");
    }
}
