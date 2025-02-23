package alessandrosalerno.libmertp;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public record MERTPSymAESKey(SecretKey key,
                             IvParameterSpec iv) {
}
