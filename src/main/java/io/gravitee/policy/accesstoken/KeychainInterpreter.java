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
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeychainInterpreter
{
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenPolicy.class);

    private static final String METHOD_KEY = "_Gr1d_method";
    private static final String BASICAUTH_METHOD = "basicauth";
    private static final String BASICAUTH_USER_KEY = "user";
    private static final String BASICAUTH_PASSWORD_KEY = "pass";
    private static final String BODY_METHOD = "body";
    private static final String BODY_KEY = "body";
    private static final String HEADER_METHOD = "header";
    private static final String QUERY_METHOD = "query";
    private static final String[] RESERVED_KEYS = {"_Gr1d_appId", "_Gr1d_apiId", "_Gr1d_gw", "_Gr1d_method", "_Gr1d_hash"};


    private final JSONArray apiList;
    private HashMap<String, String> headers = new HashMap<String, String>();
    private String queryString = "";
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
                case KeychainInterpreter.QUERY_METHOD:
                    this.addQuery(apiData);
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
        for(String key : apiData.keySet()) 
        {
            if (!KeychainInterpreter.isReservedKey(key)) 
            {
                this.headers.put(key, apiData.getString(key));
            }
        }
        KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] ADD HEADERS."));
    }

    private void addBody(JSONObject apiData)
    {
        this.body = apiData.getString(KeychainInterpreter.BODY_KEY);
        KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] ADD BODY: %s", this.getBody()));
    }

    private void addQuery(JSONObject apiData)
    {
        this.queryString = String.join("&", 
            apiData.toMap().entrySet().stream()
            .filter(entry -> !KeychainInterpreter.isReservedKey(entry.getKey()))
            .map(entry -> {
                return String.format("%s=%s", entry.getKey(), entry.getValue());
            })
            .collect(Collectors.toList())
        );

        KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] ADD QUERY: %s", this.queryString));
    }

    public String applyQuery(String url)
    {
        if ((this.queryString != null) && (this.queryString.length() > 0))
        {
            if (url.indexOf("?") > -1)
            {
                url += String.format("&%s", this.queryString);
            }
            else
            {
                url += String.format("?%s", this.queryString);
            }
            KeychainInterpreter.LOGGER.info(String.format("[Keychain->AccessToken] APPLY QUERY: %s", url));
        }
        return url;
    }

    private static Boolean isReservedKey(String key) {
        Boolean isReserved = false;
        for (String reservedKey : KeychainInterpreter.RESERVED_KEYS) {
            isReserved |= key.equals(reservedKey);
        }
        return isReserved;
    }
}