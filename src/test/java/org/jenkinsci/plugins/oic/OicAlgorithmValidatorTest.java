package org.jenkinsci.plugins.oic;

import jenkins.security.FIPS140;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

class OicAlgorithmValidatorTest {

    private MockedStatic<FIPS140> fips140Mock;

    @BeforeEach
    void setUp() {
        fips140Mock = mockStatic(FIPS140.class);
    }

    @Test
    void isAlgorithmFipsCompliant() {
        fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
        System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
        assertTrue(OicAlgorithmValidator.isAlgorithmNotFipsCompliant(""));
        assertTrue(OicAlgorithmValidator.isAlgorithmNotFipsCompliant(" "));
        assertTrue(OicAlgorithmValidator.isAlgorithmNotFipsCompliant("invalid-algo"));

        String[] validAlgoArray = {
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384", "ES512", "PS256", "PS384",
            "PS512"
        };
        for (String algo : validAlgoArray) {
            assertFalse(OicAlgorithmValidator.isAlgorithmNotFipsCompliant(algo));
        }
        assertTrue(OicAlgorithmValidator.isAlgorithmNotFipsCompliant("EdDSA"));
        assertTrue(OicAlgorithmValidator.isAlgorithmNotFipsCompliant("Ed25519"));
        assertTrue(OicAlgorithmValidator.isAlgorithmNotFipsCompliant("Ed448"));
        System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "false");
    }
}
