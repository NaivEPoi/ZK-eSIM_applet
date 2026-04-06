package zk.esim.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.RandomData;

final class RandomDataUtil {

    private RandomDataUtil() {
    }

    @SuppressWarnings("deprecation")
    static RandomData createRandom() {
        final byte[] algs = new byte[] {
                RandomData.ALG_SECURE_RANDOM,
                RandomData.ALG_PSEUDO_RANDOM
        };

        byte i = 0;
        while (i < (byte) algs.length) {
            try {
                return RandomData.getInstance(algs[i]);
            } catch (Throwable ignored) {
                i++;
            }
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    static void fillRandom(RandomData rnd, byte[] out, short off, short len) {
        rnd.generateData(out, off, len);
    }
}
