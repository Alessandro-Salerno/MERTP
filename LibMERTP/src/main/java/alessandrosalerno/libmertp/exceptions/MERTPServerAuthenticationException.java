package alessandrosalerno.libmertp.exceptions;

public class MERTPServerAuthenticationException extends Exception {
    public MERTPServerAuthenticationException() {
        super("Unable to authenticate server due to signature mismatch");
    }
}
