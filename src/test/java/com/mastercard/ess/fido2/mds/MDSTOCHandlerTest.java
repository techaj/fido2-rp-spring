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

package com.mastercard.ess.fido2.mds;

import com.fasterxml.jackson.databind.JsonNode;
import com.mastercard.ess.fido2.Fido2Application;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = Fido2Application.class)
public class MDSTOCHandlerTest {

    @Autowired
    MDSTOCHandler handler;

    @Autowired
    @Qualifier("tocEntries")
    Map<String, JsonNode> tocEntries;

    @Autowired


    @Before
    public void setup() {

    }

    @Test
    public void testTOC() {
        Assert.assertTrue(!tocEntries.isEmpty());
    }
}
