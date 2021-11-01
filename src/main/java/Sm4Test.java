import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * Created by alpha on 2021/11/1.
 */
public class Sm4Test {

    private static final String BLUETOOTH_NAME = "TCHGAS_BTC800001";
    /** 蓝牙设备名称的十六进制编码 */
    private static final String BLUETOOTH_HEX_NAME = "5443484741535F425443383030303031";
    /** 主密钥 */
    private static final String PRIME_KEY = "5348414E58495A484958494E46454948";
    /** 散列后的二级密钥 */
    private static final String SECONDARY_KEY = "B5EAF298E5095DC0FF26BEB9A7853183";

    private static final String MOCK_CONTENT = "B5EAF298";

    private static final int MODE = 16;


    public static void main(String[] args) {

        // 十六进制字符串
        String hexStr = toHex("sm4对称加密<pkCs5>演示←←");
        byte[] data = Hex.decode(hexStr);
        System.out.println("data " + Hex.toHexString(data));
        byte[] encryptedResult = encryptData(data);
        byte[] decryptedResult = decryptData(encryptedResult);
        try {
            System.out.println("data " + new String(decryptedResult, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] encryptData(byte[] data) {
        byte[] content = formatContent(data);
        byte[] key = generateSecondaryKey(BLUETOOTH_NAME);
        byte[] result = null;
        try {
            result = Sm4Util.encryptEcbPkcs5Padding(content, key);
            System.out.println("encrypt result " + Hex.toHexString(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private static byte[] decryptData(byte[] data) {
        byte[] result = null;
        byte[] key = generateSecondaryKey(BLUETOOTH_NAME);
        try {
            result = Sm4Util.decryptEcbPkcs5Padding(data, key);
            // 解析得到原二进制字符串
            result = parseResponse(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;

    }

    private static byte[] formatContent(byte[] content) {
        int contentLength = content.length;
        int paddingLength = MODE - contentLength % MODE;

        if(paddingLength == 0) {
            paddingLength = MODE;
        }
        byte[] result = new byte[contentLength + paddingLength];
        System.arraycopy(content, 0, result, 0, contentLength);
        for (int i = 0; i < paddingLength; i++) {
            result[contentLength + i] = (byte)paddingLength;
        }
        System.out.println("content size " + contentLength + " formatted content " + Hex.toHexString(result) + " padding length " + paddingLength);
        return result;
    }

    private static byte[] parseResponse(byte[] content) {
        int paddingLength = content[content.length - 1];

        byte[] result = new byte[content.length - paddingLength];
        System.arraycopy(content, 0, result, 0, result.length);
        System.out.println("parsed response " + Hex.toHexString(result));
        return result;
    }

    private static byte[] generateSecondaryKey(String bluetoothName) {
        String bluetoothHexName = toHex(bluetoothName);
        byte[] hashFactor = Hex.decode(bluetoothHexName);
        byte[] primeKey = Hex.decode(PRIME_KEY);
        try {
            byte[] secondaryKey = Sm4Util.encryptEcbPkcs5Padding(hashFactor, primeKey);

            System.out.println("secondary key " + Hex.toHexString(secondaryKey));
            return secondaryKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
    }
}
