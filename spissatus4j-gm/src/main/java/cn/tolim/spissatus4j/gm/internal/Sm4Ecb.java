package cn.tolim.spissatus4j.gm.internal;

import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Raw single-block SM4 ECB helper used exclusively by known-answer vector
 * verification. It is deliberately not part of the public cipher surface:
 * ECB mode is prohibited for data protection.
 */
public final class Sm4Ecb {

    public static final int BLOCK_LENGTH = 16;

    private Sm4Ecb() {
    }

    /** Encrypts one 16-byte block with the raw SM4 block cipher. */
    public static byte[] encryptBlock(byte[] key, byte[] block) {
        if (key == null || key.length != Sm4Keys.KEY_LENGTH) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "SM4 requires a 128-bit key");
        }
        if (block == null || block.length != BLOCK_LENGTH) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "SM4 block must be 16 bytes");
        }
        byte[] keyCopy = key.clone();
        try {
            SM4Engine engine = new SM4Engine();
            engine.init(true, new KeyParameter(keyCopy));
            byte[] output = new byte[BLOCK_LENGTH];
            engine.processBlock(block, 0, output, 0);
            return output;
        } finally {
            Arrays.fill(keyCopy, (byte) 0);
        }
    }
}