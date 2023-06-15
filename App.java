
//https://www.devglan.com/online-tools/hmac-sha256-online

package hmac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class App {
    private static final String algorithm = "HmacSHA3-512";
    

    public static byte[] hmacSha512Code(byte[] key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(message);
    }

    public static boolean hmacSha512Verify(String hmacSha512Encoded, byte[] key, byte[] message)
    {
        try{
        String result = bytesToHex(hmacSha512Code(key, message));
        if (hmacSha512Encoded.equals(result))
        {
            return true;
        } else
        {
            return false;
        }

        } catch(Exception e)
        {
            System.out.println(e.toString());
            return false;
        }

    }

  public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte hashByte : bytes) {
            int intVal = 0xff & hashByte;
            if (intVal < 0x10) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(intVal));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String sampleKey = "klucz12345";
        String sampleKeyErr = "54321kluczxdxd";

        String sampleMessage = "przykladowy tekst do zakodowania";
        String sampleMessageErr = "przykladowy tekst do zakodowania DODATKOWE ZNAKI XDXD: tak aby byl niezgodny z sampleMessage";
        try{
            //---zakodowanie
            String result = bytesToHex(hmacSha512Code(sampleKey.getBytes(), sampleMessage.getBytes()));
            System.out.println(result);

            //---sprawdzenie
            //scenariusz 1 - wlasciwy klucz - powinno być ok
            System.out.println("* Scenariusz 1: ");
            if (hmacSha512Verify(result, sampleKey.getBytes(), sampleMessage.getBytes()))
            {
                System.out.println("zgodne - wynik OK");
            } else{
                System.out.println("niezgodne");
            }

            //scenariusz 2 - błędny klucz - nie powinno być ok
            System.out.println("* Scenariusz 2: ");
            if (hmacSha512Verify(result, sampleKeyErr.getBytes(), sampleMessage.getBytes()))
            {
                System.out.println("zgodne");
            } else{
                System.out.println("niezgodne - wynik OK");
            }

            //scenariusz 3 - błędny tekst - nie powinno być ok
            System.out.println("* Scenariusz 3: ");
            if (hmacSha512Verify(result, sampleKey.getBytes(), sampleMessageErr.getBytes()))
            {
                System.out.println("zgodne");
            } else{
                System.out.println("niezgodne - wynik OK");
            }

        } catch(Exception e)
        {
            System.out.println(e.toString());
        }
      
    }


    

     

    
}
