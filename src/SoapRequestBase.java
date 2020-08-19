import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public abstract class SoapRequestBase {

    protected String xml;
    protected HttpURLConnection webRequest;

    protected SoapRequestBase(String url, String SOAPAction) throws IOException {
        this.xml = null;
        this.webRequest = webRequest(url, SOAPAction);
    }

    private static HttpURLConnection webRequest(String _url, String SOAPAction) throws IOException {
        final int maxTimeMilliseconds = 15000;
        final URL url = new URL(_url);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // set the request method and properties.
        conn.setDoInput(true);
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setReadTimeout(maxTimeMilliseconds);
        conn.setConnectTimeout(maxTimeMilliseconds);
        conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
        conn.setRequestProperty("SOAPAction", SOAPAction);

        return conn;
    }

    protected String createDigest(String sourceData) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] encodedHash = digest.digest(sourceData.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encodedHash);
    }

    protected String sign(String sourceData, PrivateKey privateKey) throws
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign(privateKey);
        sig.update(sourceData.getBytes(StandardCharsets.UTF_8));
        byte[] signData = sig.sign();
        return Base64.getEncoder().encodeToString(signData);
    }
}
