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

package com.mastercard.ess.fido2.assertion;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/assertion")
class AssertionController {
    @Autowired
    private AssertionService assertionService;

    @PostMapping(value = {"/options"}, produces = {"application/json"}, consumes = {"application/json"})
    JsonNode register(@RequestBody JsonNode params) {
        return assertionService.options(params);
    }


    @PostMapping(value = {"/result"}, produces = {"application/json"}, consumes = {"application/json"})
    JsonNode verify(@RequestBody JsonNode params) {
        return assertionService.verify(params);
    }
}
