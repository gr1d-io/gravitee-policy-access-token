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

import io.gravitee.policy.accesstoken.configuration.AccessTokenPolicyConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;
import java.io.OutputStream;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;

import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.common.http.HttpStatusCode;

import java.io.StringWriter;
import java.io.PrintWriter;

public class AccessTokenRequest
{
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenPolicy.class);
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final String TOKEN_TYPE_KEY = "token_type";
    private static final String EXPIRES_IN_KEY = "expires_in";

    private String url;
    private Map<String, String> headers;
    private String body;
    private byte[] bodyBytes;

    public AccessTokenRequest(String url, Map<String, String> headers, String body) throws UnsupportedEncodingException
    {
        this.url = url;
        this.headers = headers;
        this.body = body;
        this.bodyBytes = body.getBytes("UTF-8");
    }

    public void doRequest(Handler<AsyncResult<AccessToken>> accessTokenHandler, AccessTokenPolicyConfiguration policyConfiguration) throws IOException {

        try{
            Vertx vertx = Vertx.currentContext().owner();
           // Vertx vertx = Vertx.vertx();
            HttpClient httpClient = vertx.createHttpClient();
            HttpMethod method = HttpMethod.POST;
            if (policyConfiguration.getHttpMethod() != null) {
                method = policyConfiguration.getHttpMethod();
            }
            AccessTokenRequest.LOGGER.warn("CALLING URL: " + method + " " + url);
            HttpClientRequest httpClientRequest = httpClient
                .requestAbs(method, url)
                .handler(res -> {
                    AccessTokenRequest.LOGGER.warn("URL RESPONSE : " + res.statusCode());
                    if (res.statusCode() < 500) {
                        res.bodyHandler(new Handler<Buffer>() {
                            @Override
                            public void handle(Buffer buffer) {
                                String rawData = buffer.toString();
                                AccessTokenRequest.LOGGER.warn("ACCESS TOKEN RESPONSE : " + rawData);
                                JSONObject jsonObject = new JSONObject(rawData);
    
                                String responseKey = policyConfiguration.getResponseKey();
                                if (responseKey == null || responseKey.isEmpty()) {
                                    responseKey = AccessTokenRequest.ACCESS_TOKEN_KEY;
                                }
                                String accessToken = jsonObject.has(responseKey) ? jsonObject.getString(responseKey) : "";
                                String tokenTypeConfig = policyConfiguration.getTokenType();
                                if (tokenTypeConfig == null)
                                {
                                    tokenTypeConfig = "";
                                }
                                String tokenType = "";
                                AccessTokenRequest.LOGGER.warn("[Keychain->AccessToken] tokenTypeConfig: " + tokenTypeConfig);
                                switch(tokenTypeConfig)
                                {
                                    case "NORMAL":
                                        tokenType = "";
                                        break;
                                    case "BEARER":
                                        tokenType = "Bearer";
                                        break;
                                    default:
                                        tokenType = jsonObject.has(AccessTokenRequest.TOKEN_TYPE_KEY) ? jsonObject.getString(AccessTokenRequest.TOKEN_TYPE_KEY) : "";
                                        break;
                                }
                                AccessTokenRequest.LOGGER.warn("[Keychain->AccessToken] tokenType: " + tokenType);
                                Long expiresIn = jsonObject.has(AccessTokenRequest.EXPIRES_IN_KEY) ? jsonObject.getLong(AccessTokenRequest.EXPIRES_IN_KEY) : -1;

                                accessTokenHandler.handle(Future.succeededFuture(new AccessToken(accessToken, tokenType, expiresIn, rawData)));
                            }
                        });
                    }
                    else {
                        accessTokenHandler.handle(Future.failedFuture("Error on reading keychain data. 1->" + res.statusMessage()));
                    }
                });
            /* Headers */
            for(Map.Entry<String, String> entry : this.headers.entrySet())
            {
                httpClientRequest.putHeader(entry.getKey(), entry.getValue());
            }
            /* Body */
            if (this.body != null && !this.body.isEmpty()) {
                httpClientRequest.putHeader("Content-Length", String.valueOf(this.bodyBytes.length));
                httpClientRequest.write(this.body);
            }
            httpClientRequest.exceptionHandler(e -> {
                StringWriter outError = new StringWriter();
                e.printStackTrace(new PrintWriter(outError));
                String errorString = outError.toString();
                AccessTokenRequest.LOGGER.warn("[Keychain->AccessToken] *** ERROR ***: " + errorString);
                accessTokenHandler.handle(Future.failedFuture("Error on reading keychain data. 2"));
            });
            /* Call HTTP Request */
            httpClientRequest.end();
        }
        catch (Exception e) {
            StringWriter outError = new StringWriter();
            e.printStackTrace(new PrintWriter(outError));
            String errorString = outError.toString();
            AccessTokenRequest.LOGGER.warn("[Keychain->AccessToken] *** ERROR ***: " + errorString);
            accessTokenHandler.handle(Future.failedFuture("Error on reading keychain data. 3"));
        }
    }
}