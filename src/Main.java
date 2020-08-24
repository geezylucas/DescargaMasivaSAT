import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {

    final static String urlAutentica = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc";
    final static String urlAutenticaAction = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica";

    final static String urlSolicitud = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
    final static String urlSolicitudAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga";

    final static String urlVerificarSolicitud = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc";
    final static String urlVerificarSolicitudAction = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga";

    final static String urlDescargarSolicitud = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc";
    final static String urlDescargarSolicitudAction = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar";

    final static char[] pwdPFX = "".toCharArray(); // PFX's password
    final static String rfc = "";
    final static String dateStart = "2020-08-24"; // yyyy-MM-dd
    final static String dateEnd = "2020-08-24"; // yyyy-MM-dd

    static X509Certificate certificate = null;
    static PrivateKey privateKey = null;

    public static void main(String[] args) throws Exception {
        String filePath = "";
        File filePFX = new File(filePath);

        // Get certificate and private key from PFX file
        certificate = getCertificate(filePFX);
        privateKey = getPrivateKey(filePFX);

        // Get Token
        String token = "WRAP access_token=\"" + decodeValue(getToken()) + "\"";

        // Get idRequest with token obtained
        String idRequest = getRequest(token);

        // Get idPackages with token and idRequest obtained
        String idPackages = getVerifyRequest(token, idRequest);

        // Get package in Base64 with token and idPackages obtained
        String packageString = getDownload(token, idPackages);

        System.out.println(packageString);
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
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
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

        return authentication.send(null);
    }

    /**
     * Get XML response through SAT's web service and extract idRequest from it
     *
     * @param token
     * @return
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static String getRequest(String token)
            throws CertificateEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IOException {
        Request request = new Request(urlSolicitud, urlSolicitudAction);
        request.setTypeRequest("CFDI");

        // Send empty in rfcEmisor if you want to get receiver packages
        // or send empty in rfcReceptor if you want to get sender packages
        request.generate(certificate, privateKey, rfc, "", rfc, dateStart, dateEnd);

        return request.send(token);
    }

    /**
     * Get XML response through SAT's web service and extract idPackages from it
     *
     * @param token
     * @param idRequest
     * @return
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static String getVerifyRequest(String token, String idRequest)
            throws CertificateEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IOException {
        VerifyRequest verifyRequest = new VerifyRequest(urlVerificarSolicitud, urlVerificarSolicitudAction);
        verifyRequest.generate(certificate, privateKey, idRequest, rfc);

        return verifyRequest.send(token);
    }

    /**
     * Get XML response through SAT's web service and extract Base64's package from it
     *
     * @param token
     * @param idPackage
     * @return
     * @throws IOException
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String getDownload(String token, String idPackage)
            throws IOException,
            CertificateEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {
        Download download = new Download(urlDescargarSolicitud, urlDescargarSolicitudAction);
        download.generate(certificate, privateKey, rfc, idPackage);

        return download.send(token);
    }

    /**
     * Decodes a URL encoded string using `UTF-8`
     *
     * @param value
     * @return
     */
    public static String decodeValue(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex.getCause());
        }
    }
}
