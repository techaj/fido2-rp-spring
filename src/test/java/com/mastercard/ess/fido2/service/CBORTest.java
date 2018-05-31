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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.io.IOException;
import java.util.Base64;
import java.util.Random;
import org.junit.Assert;
import org.junit.Test;

public class CBORTest {

    Random r = new Random();

    class SomeStructure{
        @JsonProperty
        int counter;

        @JsonProperty
        String message;

        public int getCounter() {
            return counter;
        }

        public SomeStructure setCounter(int counter) {
            this.counter = counter;
            return this;
        }

        public String getMessage() {
            return message;
        }

        public SomeStructure setMessage(String message) {
            this.message = message;
            return this;
        }
    }

    @Test
    public void cborTest() throws IOException {
        CBORFactory cf = new CBORFactory();
        ObjectMapper om = new ObjectMapper(cf);

        SomeStructure ss = new SomeStructure();
        byte[] data = new byte[256];
        r.nextBytes(data);
        ss.message = "Some random message " + Base64.getEncoder().encodeToString(data);
        ss.counter = 1;

        byte[] cborMessage = om.writeValueAsBytes(ss);

        JsonNode node = om.readTree(cborMessage);
        JsonNode message = node.get("message");
        JsonNode counter = node.get("counter");
        Assert.assertTrue(message.asText().equals(ss.message));
        Assert.assertTrue(counter.asInt()==ss.counter);
    }
}
