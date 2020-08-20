import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {
    final static char[] pwdPFX = "1234".toCharArray();

    final static String urlAutentica = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc";
    final static String urlAutenticaAction = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica";

    static X509Certificate certificate = null;
    static PrivateKey privateKey = null;

    public static void main(String[] args) throws Exception {
        String filePath = "/Users/geezylucas/Documents/Python37/datasensible/FIEL/pfx.pfx";
        File filePFX = new File(filePath);
        certificate = getCertificate(filePFX);
        privateKey = getPrivateKey(filePFX);

        // Get Token
        String token = getToken();
        System.out.println(token);
    }

    /**
     * Get a certificate through a pfx file
     *
     * @param file
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static X509Certificate getCertificate(File file)
            throws KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(file), pwdPFX);
        String alias = ks.aliases().nextElement();

        return (X509Certificate) ks.getCertificate(alias);
    }

    /**
     * Get a private key through a pfx file
     *
     * @param file
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static PrivateKey getPrivateKey(File file)
            throws KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(file), pwdPFX);
        String alias = ks.aliases().nextElement();

        return (PrivateKey) ks.getKey(alias, pwdPFX);
    }

    /**
     * Get XML response through SAT's web service and extract token from it
     *
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws CertificateEncodingException
     */
    public static String getToken()
            throws IOException,
            NoSuchAlgorithmException,
            SignatureException,
            InvalidKeyException,
            CertificateEncodingException {
        Authentication authentication = new Authentication(urlAutentica, urlAutenticaAction);
        authentication.generate(certificate, privateKey);

        return authentication.send();
    }
}
