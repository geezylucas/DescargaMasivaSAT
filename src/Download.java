import org.w3c.dom.Document;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Download extends RequestBase {

    /**
     * Constructor of Download class
     *
     * @param url
     * @param SOAPAction
     */
    protected Download(String url, String SOAPAction) {
        super(url, SOAPAction);
    }

    @Override
    protected String getResult(String xmlResponse) {
        Document doc = convertStringToXMLDocument(xmlResponse);

        //Verify XML document is build correctly
        if (doc != null)
            return doc.getElementsByTagName("Paquete")
                    .item(0)
                    .getTextContent();

        return null;
    }

    /**
     * Generate XML to send through SAT's web service
     *
     * @param certificate
     * @param privateKey
     * @param rfcSolicitante
     * @param idPackage
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws CertificateEncodingException
     */
    public void generate(X509Certificate certificate, PrivateKey privateKey, String rfcSolicitante, String idPackage)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException {
        String canonicalTimestamp = "<des:PeticionDescargaMasivaTercerosEntrada xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\">" +
                "<des:peticionDescarga IdPaquete=\"" + idPackage + "\" RfcSolicitante=\"" + rfcSolicitante + "></des:peticionDescarga>" +
                "</des:PeticionDescargaMasivaTercerosEntrada>";

        String digest = createDigest(canonicalTimestamp);

        String canonicalSignedInfo = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod>" +
                "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>" +
                "<Reference URI=\"#_0\">" +
                "<Transforms>" +
                "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform>" +
                "</Transforms>" +
                "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>" +
                "<DigestValue>" + digest + "</DigestValue>" +
                "</Reference>" +
                "</SignedInfo>";

        String signature = sign(canonicalSignedInfo, privateKey);

        this.setXml("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\" xmlns:xd=\"http://www.w3.org/2000/09/xmldsig#\">" +
                "<s:Header/>" +
                "<s:Body>" +
                "<des:PeticionDescargaMasivaTercerosEntrada>" +
                "<des:peticionDescarga IdPaquete=\"" + idPackage + "\" RfcSolicitante=\"" + rfcSolicitante + "\">" +
                "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                "<SignedInfo>" +
                "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
                "<Reference URI=\"#_0\">" +
                "<Transforms>" +
                "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                "</Transforms>" +
                "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
                "<DigestValue>" + digest + "</DigestValue>" +
                "</Reference>" +
                "</SignedInfo>" +
                "<SignatureValue>" + signature + "</SignatureValue>" +
                "<KeyInfo>" +
                "<X509Data>" +
                "<X509IssuerSerial>" +
                "<X509IssuerName>" + certificate.getIssuerX500Principal() + "</X509IssuerName>" +
                "<X509SerialNumber>" + certificate.getSerialNumber() + "</X509SerialNumber>" +
                "</X509IssuerSerial>" +
                "<X509Certificate>" + Base64.getEncoder().encodeToString(certificate.getEncoded()) + "</X509Certificate>" +
                "</X509Data>" +
                "</KeyInfo>" +
                "</Signature>" +
                "</des:peticionDescarga>" +
                "</des:PeticionDescargaMasivaTercerosEntrada>" +
                "</s:Body>" +
                "</s:Envelope>");
    }
}
