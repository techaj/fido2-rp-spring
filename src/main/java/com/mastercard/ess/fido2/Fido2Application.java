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

package com.mastercard.ess.fido2;

import com.mastercard.ess.fido2.config.GlobalBeans;
import com.mastercard.ess.fido2.config.H2PersistenceConfiguration;
import com.mastercard.ess.fido2.config.WebSecurityConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({
        H2PersistenceConfiguration.class,
        WebSecurityConfig.class,
        GlobalBeans.class
})
public class Fido2Application {
        public static void main(String[] args) {
            SpringApplication.run(Fido2Application.class, args);
        }

    }



