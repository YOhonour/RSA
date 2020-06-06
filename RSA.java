package RSA;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.ParseException;

public class RSA {

    private static int qSizeInBits = 160;
    private static int pSizeInBits = 160;

    private BigInteger p = new BigInteger("847647065341988927084956781179654683795531878237");
    private BigInteger q = new BigInteger("1195126651318115928383072868944738386099589163557");
    private BigInteger n;
    private BigInteger fi_n;
    private BigInteger e;//公钥
    private BigInteger d;//私钥
    public RSA(){
        n = p.multiply(q);
        fi_n = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        //随机生成公钥
        e = new BigInteger(fi_n.toString().length()-2,new SecureRandom());//随机生成一个素数
        boolean f = true;
        while (f){
            try {
                d = e.modInverse(fi_n);//求逆元
                break;
            }catch (Exception e){
                f = true;
            }
        }
    }
    public RSA(String pStr,String qStr,String eStr) throws ParseException {
        e = new BigInteger(eStr);//随机生成一个素数
        if (!Utils.isPrime(e,16)){
            throw new ParseException("要求公钥e为素数！",0);
        }if (!Utils.isPrime(p,16)){
            throw new ParseException("要求p为素数！",0);
        }if (!Utils.isPrime(q,16)){
            throw new ParseException("要求q为素数！",0);
        }
        p = new BigInteger(pStr);
        q = new BigInteger(qStr);
        n = p.multiply(q);
        fi_n = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        //随机生成公钥
        d = e.modInverse(fi_n);//求逆元
    }
    public RSA(String pStr,String qStr) throws ParseException {
        e = new BigInteger(pSizeInBits,new SecureRandom());//随机生成一个素数
        if (!Utils.isPrime(p,16)){
            throw new ParseException("要求p为素数！",0);
        }if (!Utils.isPrime(q,16)){
            throw new ParseException("要求q为素数！",0);
        }
        p = new BigInteger(pStr);
        q = new BigInteger(qStr);
        n = p.multiply(q);
        fi_n = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        //随机生成公钥
        d = e.modInverse(fi_n);//求逆元
    }

    public byte[] RSAEncode(byte[] m){
        BigInteger M = new BigInteger(m);
        BigInteger C = M.modPow(e,n);
        return C.toByteArray();
    }
    public byte[] RSADecode(byte[] c){
        BigInteger C = new BigInteger(c);
        BigInteger M = C.modPow(d,n);
        return M.toByteArray();
    }public String RSAEncode(String m){
        BigInteger M = new BigInteger(m);
        BigInteger C = M.modPow(e,n);
        return C.toString();
    }
    public String RSADecode(String c){
        BigInteger C = new BigInteger(c);
        BigInteger M = C.modPow(d,n);
        return M.toString();
    }
    public String RSAEncode(String m,int hex){
        BigInteger M = new BigInteger(m,16);
        BigInteger C = M.modPow(e,n);
        return C.toString();
    }
    public String RSADecode(String c,int hex){
        BigInteger C = new BigInteger(c,16);
        BigInteger M = C.modPow(d,n);
        return M.toString();
    }
    public void printPublicKey(){
        System.out.println("公钥e:"+e );
    }
    public void printPriviteKey(){
        System.out.println("私钥d:"+d );
    }
    public static char[] byteToChar(byte[] b){
        char[] chars = new char[b.length*2];
        for (int i = 0; i < b.length; i++) {
            chars[i*2] = (char)(b[i] >> 4);
            chars[i*2] = (char)(b[i] & 0x0f);
        }
        return chars;
    }
    public static byte[] charToByte(char[] chars){
        byte[] bytes = new byte[chars.length/2];
        for (int i = 0; i < chars.length/2; i++) {
            bytes[i*2] = (byte) (((chars[i] & 0x0f) << 4) | (chars[i]& 0x0f));
        }
        return bytes;
    }
    public static void main(String[] args) throws ParseException {
//        RSA rsa = new RSA("43","59","13");
        RSA rsa = new RSA( );
        System.out.println(rsa.e.multiply(rsa.d).mod(rsa.fi_n));
        rsa.printPublicKey();
        rsa.printPriviteKey();
        String m = "1442";
        System.out.println("明文为："+m);
        String rsaEncode = rsa.RSAEncode(m);
        String C = new String(rsaEncode);
        System.out.println("加密后C="+C);
//        byte[] bytes = rsa.RSADecode(C.getBytes());
        String bytes = rsa.RSADecode(C );
        System.out.println("解密后M'="+bytes);
//        BigInteger p = BigInteger.probablePrime(qSizeInBits, new SecureRandom());
//        BigInteger q = BigInteger.probablePrime(qSizeInBits, new SecureRandom());
//        System.out.println(p);
//        System.out.println(q);
    }

}
