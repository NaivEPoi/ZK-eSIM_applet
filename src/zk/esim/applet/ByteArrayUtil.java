package zk.esim.applet;

final class ByteArrayUtil {

    private ByteArrayUtil() {
    }

    static boolean equals(byte[] left, short leftOff, byte[] right, short rightOff, short len) {
        short i = 0;
        while (i < len) {
            if (left[(short) (leftOff + i)] != right[(short) (rightOff + i)]) {
                return false;
            }
            i++;
        }
        return true;
    }
}
