package alessandrosalerno.libmertp.exceptions;

import alessandrosalerno.libmertp.LibMERTP;

public class MERTPVersionMismatchException extends Exception {
   private final short otherVersion;

    public MERTPVersionMismatchException(short otherVersion) {
        super("Trying to parse MERTP message from endpoint running on MERTP/" + String.format("%06d", otherVersion)
                + ", but we're running on MERTP/" + String.format("%06d", LibMERTP.MERTP_VERSION));
        this.otherVersion = otherVersion;
    }

    public short getOtherVersion() {
        return this.otherVersion;
    }
}
