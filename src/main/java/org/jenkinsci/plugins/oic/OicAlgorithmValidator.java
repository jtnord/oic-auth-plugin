package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.LinkedHashSet;
import java.util.Set;
import jenkins.security.FIPS140;

public class OicAlgorithmValidator {

    /**
     *  Checks if the algorithm used for OIC configuration is FIPS compliant.
     */
    public static boolean isAlgorithmNotFipsCompliant(@NonNull String argAlgorithm) {
        if (FIPS140.useCompliantAlgorithms()) {
            Set<JWSAlgorithm> jwsSupportedAlgorithms = new LinkedHashSet<>();
            jwsSupportedAlgorithms.addAll(MACSigner.SUPPORTED_ALGORITHMS);
            jwsSupportedAlgorithms.addAll(RSASSASigner.SUPPORTED_ALGORITHMS);
            jwsSupportedAlgorithms.addAll(ECDSASigner.SUPPORTED_ALGORITHMS);

            if (!jwsSupportedAlgorithms.isEmpty()) {
                return jwsSupportedAlgorithms.stream()
                        .map(JWSAlgorithm::getName)
                        .noneMatch(name -> name.equals(argAlgorithm));
            }
        }
        return false;
    }
}
