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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;
import java.io.OutputStream;


public class AccessTokenRequest
{
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenPolicy.class);
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final String TOKEN_TYPE_KEY = "token_type";
    private static final String EXPIRES_IN_KEY = "expires_in";

    private String url;
    private String method;
    private Map<String, String> headers;
    private String body;
    private byte[] bodyBytes;

    public AccessTokenRequest(String url, String method, Map<String, String> headers, String body) throws UnsupportedEncodingException
    {
        this.url = url;
        this.method = method.toUpperCase();
        this.headers = headers;
        this.body = body;
        this.bodyBytes = body.getBytes("UTF-8");
    }

    public String doRequest() throws IOException {
        URL obj = new URL(this.url);
        HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
        con.setRequestMethod(this.method);
        
        /* Headers */
        for(Map.Entry<String, String> entry : this.headers.entrySet())
        {
            con.addRequestProperty(entry.getKey(), entry.getValue());
        }

        /* Body */
        if (this.body != null && !this.body.isEmpty()) {
            con.setDoOutput(true);
            OutputStream bodyOS = con.getOutputStream();
            bodyOS.write(this.bodyBytes);
            bodyOS.close();
        }
        
        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null)
            response.append(inputLine);
        in.close();

        return response.toString();
    }

    public JSONObject doRequestJSON() throws IOException {
        return new JSONObject(this.doRequest());
    }

    public AccessToken getAccessToken() throws IOException {
        JSONObject jsonObject = this.doRequestJSON();

        String accessToken = jsonObject.getString(AccessTokenRequest.ACCESS_TOKEN_KEY);
        String tokenType = jsonObject.getString(AccessTokenRequest.TOKEN_TYPE_KEY);
        Long expiresIn = jsonObject.getLong(AccessTokenRequest.EXPIRES_IN_KEY);

        return new AccessToken(accessToken, tokenType, expiresIn);
    }
}