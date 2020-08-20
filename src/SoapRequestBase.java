import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public abstract class SoapRequestBase {

    private String xml;
    private final String url;
    private final String SOAPAction;

    protected SoapRequestBase(String url, String SOAPAction) {
        this.xml = null;
        this.url = url;
        this.SOAPAction = SOAPAction;
    }

    public void setXml(String xml) {
        this.xml = xml;
    }

    protected String createDigest(String sourceData) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.reset();
        digest.update(sourceData.getBytes());
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    protected String sign(String sourceData, PrivateKey privateKey) throws
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign(privateKey);
        sig.update(sourceData.getBytes());
        byte[] signData = sig.sign();
        return Base64.getEncoder().encodeToString(signData);
    }

    protected String send() throws IOException {
        URL url = new URL(this.url);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // Set timeout as per needs
        conn.setConnectTimeout(20000);
        conn.setReadTimeout(20000);

        // Set DoOutput to true if you want to use URLConnection for output.
        // Default is false
        conn.setDoOutput(true);

        // Set Headers
        conn.setRequestProperty("Accept-Charset", "UTF_8");
        conn.setRequestProperty("Content-type", "text/xml; charset=utf-8");
        conn.setRequestProperty("SOAPAction", SOAPAction);

        // Write XML
        OutputStream outputStream = conn.getOutputStream();
        outputStream.write(xml.getBytes(StandardCharsets.UTF_8));
        outputStream.flush();
        outputStream.close();

        // Check the error stream first, if this is null then there have been no issues with the request
        InputStream inputStream = conn.getErrorStream();
        if (inputStream == null)
            inputStream = conn.getInputStream();

        // Read XML
        byte[] res = new byte[2048];
        int i;
        StringBuilder response = new StringBuilder();
        while ((i = inputStream.read(res)) != -1) {
            response.append(new String(res, 0, i));
        }
        inputStream.close();

        return response.toString();
    }
}
