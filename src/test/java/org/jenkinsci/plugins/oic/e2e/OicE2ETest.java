package org.jenkinsci.plugins.oic.e2e;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.either;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class OicE2ETest {

    private static final String REALM = "test-realm";

    @Rule
    public KeycloakContainer keycloak = new KeycloakContainer().useTls()/*.withRealmImportFile("org/jenkinsci/plugins"
                                                                                             + "/oic/e2e/realm.json")*/;

    @Before
    public void setUpKeyloak() {
        try (Keycloak keycloakAdmin = keycloak.getKeycloakAdminClient()) {
            RealmRepresentation testRealm = new RealmRepresentation();
            testRealm.setRealm(REALM);
            testRealm.setId(REALM);
            testRealm.setDisplayName(REALM);

            keycloakAdmin.realms().create(testRealm);

            // Add groups
            GroupRepresentation devs = new GroupRepresentation();
            devs.setName("devs");
            GroupRepresentation sales = new GroupRepresentation();
            sales.setName("sales");
            GroupRepresentation employees = new GroupRepresentation();
            employees.setName("employees");
            employees.setSubGroups(Arrays.asList(devs, sales));
            testRealm.setGroups(Arrays.asList(employees));

            RealmResource theNew = keycloakAdmin.realm(REALM);
            try (Response r = theNew.groups().add(employees)) {
                assertThat(r.getStatus(), either(is(200)).or(is(201)));
            }

            UserRepresentation bob = new UserRepresentation();
            bob.setEmail("bob@acme.org");
            bob.setUsername("bob");
            bob.setGroups(Arrays.asList("/employees", "/employees/devs"));
            bob.setEmailVerified(true);
            bob.setEnabled(true);
            UserRepresentation john = new UserRepresentation();
            john.setEmail("john@acme.org");
            john.setUsername("john");
            john.setGroups(Arrays.asList("/employees", "/employees/sales"));
            john.setEmailVerified(true);
            john.setEnabled(true);
            testRealm.setUsers(Arrays.asList(bob, john));

            theNew = keycloakAdmin.realm(REALM);
            try (Response r = theNew.users().create(bob)) {
                System.out.println(r.getStatusInfo().getReasonPhrase());
                assertThat(r.getStatus(), either(is(200)).or(is(201)));
            }
            try (Response r = theNew.users().create(john)) {
                assertThat(r.getStatus(), either(is(200)).or(is(201)));
            }

            // Tried as well:
            //testRealm.setGroups(Arrays.asList(employees));
            //testRealm.setUsers(Arrays.asList(bob, john));
            //keycloakAdmin.realms().create(testRealm);

            // Assert that the realm is properly created
            RealmRepresentation created = keycloakAdmin.realm(REALM).toRepresentation();
            assertNotNull("test realm is created", created);
            assertThat("groups are created", created.getGroups().stream().map(GroupRepresentation::getName).collect(Collectors.toList()),
                       containsInAnyOrder("employees", "devs", "sales"));
            assertThat("users are created", created.getUsers().stream().map(UserRepresentation::getUsername).collect(Collectors.toList()),
                       containsInAnyOrder("bob", "john"));
        }
    }

    @Test
    public void test() {
        System.out.println("FRAN!!!!");
        System.out.println("FRAN: " + keycloak.getAuthServerUrl());
/*
        Keycloak keycloakAdmin = keycloak.getKeycloakAdminClient();
        keycloakAdmin.realm("testrealm").groups().
*/
/*
        RealmResource realm = keycloakClient.realm(KeycloakContainer.MASTER_REALM);
        ClientRepresentation client = realm.clients().findByClientId(KeycloakContainer.ADMIN_CLI_CLIENT).get(0);
*/    }

}
