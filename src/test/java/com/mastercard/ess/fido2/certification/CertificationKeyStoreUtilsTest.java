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

package com.mastercard.ess.fido2.certification;

import com.mastercard.ess.fido2.Fido2Application;
import com.mastercard.ess.fido2.service.AuthData;
import javax.net.ssl.TrustManager;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = Fido2Application.class)

public class CertificationKeyStoreUtilsTest {
    @Autowired
    CertificationKeyStoreUtils utils;

    @Before
    public void setup() {

    }

    @Test
    public void happyPathTest() {
        AuthData authData = new AuthData();
        authData.setAaguid("91dfead7-959e-4475-ad26-9b0d482be089".getBytes());
        TrustManager tm = utils.populateTrustManager(authData);
        Assert.assertTrue(tm != null);
    }
}
