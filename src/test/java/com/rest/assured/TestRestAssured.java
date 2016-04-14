package com.rest.assured;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.authentication.OAuthSignature;
import com.jayway.restassured.config.RestAssuredConfig;
import com.jayway.restassured.response.Response;
import org.testng.annotations.*;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.jayway.restassured.RestAssured.*;


/**
 * Created by gadrea on 2/24/2016.
 */

public class TestRestAssured {

    @Test
    public void testGetAccessToken() throws MalformedURLException, UnsupportedEncodingException {

        // config
        String baseUri = "http://accounts-dev.autodesk.com";
        String consumerKey = "TestConsumerKey";
        String consumerSecret = "TestConsumerSecret!";
        String username = "TestUserName";
        String password = "TestPassword";

        RestAssured.baseURI = baseUri;

        //Get request Token
        Response response = given()
                    .log().all()
                    .auth()
                    .oauth(consumerKey, consumerSecret, "", "")
                    .config(RestAssuredConfig.newConfig().oauthConfig(com.jayway.restassured.config.OAuthConfig.oauthConfig().addEmptyTokenToBaseString(false)))
                    .get("/oauth/requesttoken");

        String strResponse = response.asString();
        String requestToken = URLDecoder.decode(strResponse.split("&")[0].split("oauth_token=")[1], "UTF-8");
        String tokenSecret = URLDecoder.decode(strResponse.split("&")[1].split("oauth_token_secret=")[1], "UTF-8");

        //Fire Authorize
        response = given()
                .log().all()
                .redirects().follow(true)
                .queryParam("oauth_token",requestToken)
                .get("/oauth/authorize");

        //Fetch response details
        strResponse = response.asString();
        Map cookies = response.getCookies();
        Pattern pattern = Pattern.compile("<input name=\"__RequestVerificationToken\" type=\"hidden\" value=\"(.+?)\" />");
        Matcher matcher = pattern.matcher(strResponse);

        //Get CSRF Token
        String csrfToken = "";
        if (matcher.find())
            csrfToken = matcher.group(0).split("value=\"")[1].split("\"")[0];

        String returnUrl = baseUri + "/oauth/authorize?oauthtoken=" + requestToken;
        String referrerUrl = baseUri + "/LogOn?ReturnUrl=" + URLEncoder.encode(returnUrl,"UTF-8") ;

        //Authorize
        response = given()
                .log().all()
                .redirects().follow(true)
                .header("Accept","*/*")
                .header("Referer",referrerUrl)
                .header("Accept-Encoding","gzip, deflate")
                .header("X-Requested-With","XMLHttpRequest")
                .queryParam("ReturnUrl",returnUrl)
                .queryParam("fromSignIn","true")
                .formParam("__RequestVerificationToken",csrfToken)
                .formParam("UserName",username)
                .formParam("Password",password)
                .formParam("RememberMe","false")
                .contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .post("/Authentication/LogOn");

        //Get required details from response
        cookies = response.getCookies();
        String redirectURL = response.asString().split("data-redirect-url=\"")[1].split("\"")[0];
        System.out.println("redirectURL:" + redirectURL);

        //Explicit redirect to Authorize as POST doesn't follow redirect for 302
        response = given()
                .log().all()
                .redirects().follow(true)
                .header("Referer",referrerUrl)
                .cookies(cookies)
                .queryParam("oauth_token",requestToken)
                .queryParam("fromSignIn","true")
                .get("/oauth/authorize");

        //Get Access Token
        response = given()
                .log().all()
                .auth()
                .oauth(consumerKey, consumerSecret, requestToken, tokenSecret, OAuthSignature.QUERY_STRING)
                .get("/oauth/accesstoken");

        strResponse = response.asString();
        String accessToken = URLDecoder.decode(strResponse.split("&")[0].split("oauth_token=")[1], "UTF-8");
        String accesstokenSecret = URLDecoder.decode(strResponse.split("&")[1].split("oauth_token_secret=")[1], "UTF-8");
    }
}
