package alessandrosalerno.libmertp;

import java.security.PublicKey;

public record MERTPServerHandshake(String serverName,
                                   PublicKey serverPublicKey,
                                   MERTPSymAESKey aesKey) {
}
