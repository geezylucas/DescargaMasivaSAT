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


    final static char[] pwdPFX = "1234".toCharArray();
    final static String rfc = "PTI121203SZ0";
    final static String fechaInicial = "2019-09-01";
    final static String fechaFinal = "2019-09-03";

    static X509Certificate certificate = null;
    static PrivateKey privateKey = null;

    public static void main(String[] args) throws Exception {
        String filePath = "/Users/geezylucas/Documents/Python37/datasensible/FIEL/pfx.pfx";
        File filePFX = new File(filePath);

        // Get certificate and private key from PFX file
        certificate = getCertificate(filePFX);
        privateKey = getPrivateKey(filePFX);

        // Get Token
        String token = "WRAP access_token=\"" + decodeValue(getToken()) + "\"";

        // Get idRequest with token obtained
        //String idRequest = getRequest(token);

        // Get idPackages with token and idRequest obtained
        //String idPackages = getVerifyRequest(token, idRequest);

        // Get package in Base64 with token and idPackages obtained
        //String packageString = getDownload(token, idPackages);
        String packageString = "UEsDBBQAAAAIADohGFGwxu+GgA0AAKMYAAAoAAAAYmM0YzRmOTEtMGVlZi00N2VlLWJiZmEtYjA5MzhiNDczMDk0LnhtbO1ZSZLizJK+CsYWy9Q8lVXWM40g0DxLmzYhCSEQEmhAwI16/ZbdZr34D9RX6BBkVpE1dP+bt+u0TIEifIrP3SPcI//7P/7r6z8uh3Jyzpq2qKu3KfIKTydZldRpUeVvU9eRXujpP759TTZp8YWvD8emXsdVl00AV9V+ubTF23TbdccvEDQMw+uAvdZNDqEwjECBqtjJNjvEL0XVdnGVZNMJoP/S3geVOom7u8on9jbuXvN6/Xq4QEAhhE1+P9cWgPPfCmBGU2Xdg3R8njHs9dKmf+Cq6kNRxQj694U+OL4zjrKn7wsf8fhfTf8g/GD+E/HH/HTiffgAewXcUpZs47cpCiPMCwx+MQehviDIF4KZTuysLOu3KedGVr6dnYqApD2CQIYdA10LJlhY6uZkb1Az6E9+jeoUvBp4pp9BSWQW7Jaz0hor4ltbqPxpQG7c8txsUGy5nPPBThkMtU0xV5Ii/JaiZFyGtLczZnNMVmhqsWhkb9fBsKevehSzamduktrphM8W+vpQm/7petX65uwHaAPP86XgMTIr8wZ71LH8bKKNyHgnhYr0oVrNSG1ZtsVOMwO1P2tb1ZCLUCnn0KEvV/LavnlQGxcpLQ3ZQWuUaKF1klF6hxgLNXkIejOAtp4ZoOqCbr1da52S0lwMisvP0ZyJZ6KW9JxLXVqBUMgiaTZahQ4Il+6zlXAkVzVMnvdHpic61eZ0/DCYtY8cAl8Z3t4A+HVziI04ByAzAG+t5rOmKzZFEqdgCAY/CHz/wWESYQgaBw77RKLK8nyx43mOjXN2kDk2l11VYAdVEIfHJwurQnjRHRfXBHUQzHC5qiN5e0401hQVzmSHPJ9fVScftDwUPNMUBJ7hlL3ay3OrXPOcEwVLNPa14/rK7SOb46I5clwfylu6WG5DtBJaFM+9xfIYVh4cBuDTEc8qD89ZxBX5fDi4qHdND+Uu9uk8mru56Vtd7BPHBLOuIZA7UFovS9Y19pdIOpfAp3jRBRblcs3j2FZVYGm/9ss+DjQ4OUi7ONFv6+JuixP5KZIcyn3om3fZ67mY2z5xWGPL7kO2atHD4tO695y05YDtzD6BuVsYmH2EMoVyQHDVDocle8dhKXDAjQWe2/NR/qVaX1lMuw65iTKtUnCL1PeuycG7rm+irrLDfb2iOUgA7xvA/cLf2OVjDaHD7pFQtfaDNNxlywLHiY/1lDDAdR75VgnW1qqWOYgPPywEthNSX0LihSOcfOQc3kRP5dS7HsVSVReWXN1JBu3GXpw9flM9ePCHT+vkBZGwo0Ab1ihxC/1lGzn17/EXtXJdje/DHccfPmNun30D3udSC+jPI/04nvlen87dYbFNNHW0xxFR1dlf1J2M++PYTvw8tuO5807MVQ6/r4W9qIErLQ3f9QRPZBygb2ntxdyFxdwSQbwg4UUW2OyOJb93JISzHaSUTMQy3Cvn2m7EyZLGyaIlAbt81WaHxQPDlXhJTXfPRJaruQ6i5p5Yzk0QN+BPtGxO8HZiqfLfMU1coFt1ZGAne3ORepB5OrcQj3NvLqEKwH4YR8FaMpV7+JuzVO9XGsR0pGPo3kD+mfSYc6MtijhEmulZtu3VIOfEQmXhOW+f5ra8xgRT5FjTZVlc5oRhzElxxdYgn01+cVOdrrQLAhwbTTZXzsSyobDbpjUsipUrcUlbCrQRjx2JNZlDO7IN4XW03qfD2RANeIlWFl+t8wgipZ28cPHyZvIbE+8Mp/FVZrUzdK43IVkmofJim52xyWYrxWa1GPVbOz+Zebe97FUsCi/K9XbDNqbYw/aWvrjXVrXJ47ZjBajZnvHNPrvVg13eKi5j/X61TyB0r+ssYQ2surba9Wm2g3ZQ63NBu3arSIRN4uxalw2Ci2Qc3jhM8dSb3+2w2NohHeZnkCFcbuhSUyxBLC/5NrdTfru1GzzxMynHN4qA8FGWzoWugFbq8iBLh2GGQMixww80cpjHOazB+7mtd3lyGyKdY291zSECUyEsiD6Wne8WDrt+z91UHEQOGkxeZdmBH/PUgg3gAIHN1+zPvuKHu6941mS3Bns6FWsFBZkjBd1SDsN9P2fP4vGUY8Zip1xNFNlyt52HbNBNqtFJpq0KyZJ0f8nvb8sBDpjKpQd2kRwI+yikbSQ3fnohNsQlTStfTsxkI5M7PoICR4pu/ebkeLt+JuirMNwhe11odnCNJaoxC7KlFRRDSpxvwXGLiZc68KlzquDtSqrUUOOjXd4mM5pJr+5sI64OcArT8rGApIudkfIeMVimPaZRtE4NPCh5wxV6ah9Hne5tAYJ6I0vlpazohV/Ps5qJ4qKyLIVcI/QxCnVUCIz5GnfJXXvlO3/tmBVDEKzMhTnfSnM/1hYmnW3kXIEVNc530TVSqlsQGd0x2EA1ce3jbUj3gek2UnTkapYiHMnYBewCwZ2NwFq+RuFi1FSCpHr5yTYE/6wnKqOL8zggjD0vKe2s3A925uGkeqkEWSClxdCvt5mNLXpbMhzap6Q93hqYgC0DZmeCbUgotqSKE9fhfA2uTHLtFXaDKrTfN7GZns8h4flr2mJuw1UdkKPPd3beNP3icpvxHMq5VbsyVIqFLSSkMJzyj8OJ94iY2LVQpPsW6diLGcr1Kq2LhyFxpDKRZ1vSrxey1SqcKlmke2V0HlnX+y1tXASq6zkf0bSZHfBkb23V9TVaoOlJNJz9KaRwQhKbkj802IyE2Lzk51KCzCJ53p1WiDvj96vO5iiTSGADy9v1gRWqy6bFQi+cNYw5lhxqXWUpKPjUQJtOnOJYC9lTuf02BaNq1tVp/ShLDFcc68CmyB414lizlAWYQMjpROnzuBEvxywtkntFCWMkAep6u187dReXgIVAQe3yOvIJWZv0WdUBXpqgsMfgOxlCkhgCv8Lw9KMDAA8rK+NRLCh02rulHwNAD/4HwonrygJQIGA0BWP4C8Hz+AtOYdgLS5DsC8FgHCwRCEeyQDn07Sv0W23vssVD0dbNxMry4pBVUtEmo60kjEwn1iYB2DgygiIojNkRPBZvh3UDUDIsPRR5R7cn4CRjJzY7EcQJ793V3cVaWZIdu1HwKGTuWiwNZKI4h1M/pMz7rGlioPtaxRO26fqmnk7ctuYlQQY6Rhug791SdRfY/vQ+4cv4nBlNnQL/nQEoOIIgBEyAEhK4ukjjFAA/fVC51eOd5Z2Hp5ri+IB6DINJmk2qv/45NhCgfYjLugH0XdyMcfDkYflwrJsxhv4vr/8A/hfTD8cyO4z0375+dCxftPuXH30L8oo+Qvcx8TbV39uYR8g+Whn6BUPeh+UKhGdcfp4d4/c+KwER5a+cWn8QirgFE2NEAKUECE/4PWKNrAF2jwBl7afl3meFLO2Tj8nvq35a0FNgtV0DMg08qjG2QpKmCYymkdFL0BPH95jh++b4HDQLQbJCC2buBttZ3jejI+16XPDbFCdghiZRGMWxZyzGTFLidd3cUxRGsBcEvgPCgrjI//rP7B4LBgaT/gNo4KeuiUcnjoFnFxVI+LgsbvceRKsfRMu6AdkTP2ge+XpPHDCA3s0TR+e+dzbYGBrHuOniwyM6HJHXZF5nBVXWZNuxWEf2gF+NPmufpkHmFVmb1x/DQDDwRVGPGxAw+uFGsDsAnIDYmIurBITpaBOK0qCBIkkwN46OZBTgtuNyjGMubsE22LEggN+mFMW84j/mQBiApwx2x7y5W08h2CtDvGeOWHVSBtASZOmzy55j5BEXdp+V91j6OWDmTXy+S/55Qrw8wHnfGn8j+w70j9cR2o+c/vj+nmNv04f+73n6XSsCUzDznMGf1P5hUb8qxugfisd7hh+KgaZHy5oUf/2z+tUAFEcwDLkr+5MF0G9xfbLsKeke2OkgYttPqYhSOPPKYO/YAk33IGqtrMvA9jc6hkYZGn5FyenvBL+flu9vPyFNfFqwrNr2036IwfQrRX5G8s9ikWexzLNYo/nr31uQMfVErjZgxzgX3fOui+PIK0L9XTVjUn6owT+pkW1r0h6fJH+H5bMnnsB9Hn7syt++dpv0i1OMx9nj6BSKHBwa5ft9FZj901XVb5im//J7wN9Z+rcv8Lo78+bOnD6YfyfwjCCPu72noww4+1GzcBRGiSzDv2C4KL3grCC8MIKIvFAMTiE8RXEcKr5v4nfRj8z5fG2HfkEexQk49c+PiyJQ6bE2DE4UFKd4+P1OD1QR/3+t96+71vt0j2ezzk9XeTgOzm4Kf/fFfX7O7iO7wboszOENZ8whVxPKQRQCuAypVs/C5GJCLJtsPL9VmoUPzWxPsnGYdbN9Dtrd4zor8c2aK3ykJna7E9lnUZptYK3RPX1J523rnhZxXJ90ppr1uib6lpfGiyUebw1h5ZsCttZDJtocOnJpWZCi00Ox6K0ludkpDXTd6Tpl13s0paoT6KYFSNRtMQ72OyMFnY5U9ic5ctE57CwJ5wbtggUVVbmMuEIpEGFRupockFFEtxJr0BcXMZdsfqqKJUZy/Q2V7SNuwnaEZca6guc7fFsrvc76tlFRW8rXhmDRNlJ1jItlMBz3TbI5zHZbI1/tNOMoK75nrEj+yKnOnqCWR7btC4EiDrTG3vudp1rzqbaEfv4/w7f/AVBLAQIUABQAAAAIADohGFGwxu+GgA0AAKMYAAAoAAAAAAAAAAAAAAAAAAAAAABiYzRjNGY5MS0wZWVmLTQ3ZWUtYmJmYS1iMDkzOGI0NzMwOTQueG1sUEsFBgAAAAABAAEAVgAAAMYNAAAAAA==";

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
        request.setTipoSolicitud("CFDI");
        request.generate(certificate, privateKey, rfc, "", rfc, fechaInicial, fechaFinal);

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
