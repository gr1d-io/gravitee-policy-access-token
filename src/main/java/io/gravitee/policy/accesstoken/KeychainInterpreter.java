/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.accesstoken;
import java.util.HashMap;
import java.util.AbstractMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class KeychainInterpreter
{
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenPolicy.class);

    private static final String METHOD_KEY = "method";
    private static final String BASICAUTH_METHOD = "basicauth";
    private static final String BASICAUTH_USER_KEY = "user";
    private static final String BASICAUTH_PASSWORD_KEY = "pass";
    private static final String BODY_METHOD = "body";
    private static final String BODY_KEY = "body";
    private static final String HEADER_METHOD = "header";
    private static final String HEADER_KEY_KEY = "headerkey";
    private static final String HEADER_VALUE_KEY = "headervalue";

    private final JSONArray apiList;
    private HashMap<String, String> headers = new HashMap<String, String>();
    private String body = "";

    public HashMap<String, String> getHeaders() { return this.headers; }
    public String getBody() { return this.body; }

    public KeychainInterpreter(JSONArray apiList)
    {
        this.apiList = apiList;
        this.interpret();
    }

    private void interpret()
    {
        for(int i=0;i<this.apiList.length();i++)
        {
            JSONObject apiData = this.apiList.getJSONObject(i);
            String method = apiData.getString(KeychainInterpreter.METHOD_KEY);
            switch(method)
            {
                case KeychainInterpreter.BASICAUTH_METHOD:
                    this.addBasicAuth(apiData);
                    break;
                case KeychainInterpreter.HEADER_METHOD:
                    this.addHeader(apiData);
                    break;
                case KeychainInterpreter.BODY_METHOD:
                    this.addBody(apiData);
                    break;
                default:
                    break;
            }
        }
    }

    private void addBasicAuth(JSONObject apiData)
    {
        String user = apiData.getString(KeychainInterpreter.BASICAUTH_USER_KEY);
        String pass = apiData.getString(KeychainInterpreter.BASICAUTH_PASSWORD_KEY);
        String userPass = String.format("%s:%s", user, pass);
        String encodedHeader = java.util.Base64.getEncoder().encodeToString(userPass.getBytes());

        this.headers.put("Authorization", String.format("Basic %s", encodedHeader));

        KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] ADD BASIC AUTH: %s:%s", user, pass));

    }

    private void addHeader(JSONObject apiData)
    {
        String key = apiData.getString(KeychainInterpreter.HEADER_KEY_KEY);
        String value = apiData.getString(KeychainInterpreter.HEADER_VALUE_KEY);

        this.headers.put(key, value);
        KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] ADD HEADER: %s:%s", key, value));
    }

    private void addBody(JSONObject apiData)
    {
        this.body = apiData.getString(KeychainInterpreter.BODY_KEY);
        KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] ADD BODY: %s", body));
    }
}