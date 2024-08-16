package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

@SuppressFBWarnings(value = "WEAK_TRUST_MANAGER", justification = "User set parameter to skip verifier.")
public class AnythingGoesTrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    }

    @Override
    @SuppressFBWarnings(value = "WEAK_TRUST_MANAGER", justification = "User set parameter to skip verifier.")
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    }

    @Override
    @SuppressFBWarnings(value = "WEAK_TRUST_MANAGER", justification = "User set parameter to skip verifier.")
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

}
