/*
 * Copyright (c) 2018 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package com.mastercard.ess.fido2.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.ess.fido2.Fido2Application;
import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;


@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration(classes=Fido2Application.class)
public class AuthenticationAttestationVerifierTest {

    @Before
    public void setup(){

    }
    @Autowired
    AuthenticatorAttestationVerifier verifier;



    @Test
    public void happyPathTest() throws IOException {
        ObjectMapper om = new ObjectMapper();
        String tree = "{\"response\":{\"attestationObject\":\"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAIl9iAT2Bx4cXRrdAXvvuD67EvgvlMImG_VvDF8mzJFkAiBorNBjA1vbsMxhZpjo-_TN1BR6boZBF1p1Zhpg_XbblWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjEI7KTq6ej_qpC3Pe0kj9Ee68qUR53BXvauIUQ-TEAkIJBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIlyjnrI2kdHoWXTvt56WIrc_nQRAUjKacL9rHGNS9iSreFms1iY3nu9pzakLQ-fJRUQOYIzU5PuywLRdWiaXeGlAQIDJiABIVggDQKnUk4mIzZjiCqy0IglbjYsK4e92aOembu9rBCVYdsiWCDT0K49t0UOldqqTOqW_XEY1GPvqOWFa3xj_SNLIFj4Fw\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJocHhFUUEtZDh2UmtJMkpHT0hPSlpINmlibkJrWFBOdnd6VGZmMFJKamV3IiwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwczovL2doLTUwdjB5NTIuY29ycC5tYXN0ZXJjYXJkLm9yZzo4ODAwIn0\"},\"id\":\"iXKOesjaR0ehZdO-3npYitz-dBEBSMppwv2scY1L2JKt4WazWJjee72nNqQtD58lFRA5gjNTk-7LAtF1aJpd4Q\",\"type\":\"public-key\"}}";
        JsonNode browserResponse = om.readTree(tree);
        verifier.verifyAuthenticatorAttestationResponse(browserResponse,"gh-50v0y52.corp.mastercard.org");

    }



}
