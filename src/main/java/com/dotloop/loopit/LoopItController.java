package com.dotloop.loopit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.apache.commons.io.IOUtils;
import org.apache.http.Consts;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Date;

@Controller
public class LoopItController {

    private final Logger logger = LoggerFactory.getLogger(LoopItController.class);

    @Autowired
    CsrfTokenRepository csrfTokenRepository;

    @Value("${dotloop.oauth.client.id}")
    private String clientId;

    @Value("${dotloop.oauth.client.secret}")
    private String clientSecret;

    @Value("${dotloop.oauth.endpoint}")
    private String oauthEndpoint;

    @Value("${dotloop.oauth.redirect_url}")
    private String redirectUrl;

    @Value("${dotloop.api.endpoint}")
    private String apiEndpoint;

    private String username = "api user";

    @RequestMapping(value = "/loopit", method = RequestMethod.POST)
    @ResponseBody
    public String loopIt(
            @RequestParam(value = "profile_id", required = true) String profile_id,
            @RequestBody Loop loop) throws Exception {

        Token token = TokenStore.get(username);

        ObjectMapper mapper = new ObjectMapper();
        String data = mapper.writeValueAsString(loop);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            try {
                HttpResponse response = Request.Post(getApiBaseUrl() + "/loop-it?profile_id=" + profile_id)
                        .addHeader("Authorization", "Bearer " + token.getAccessToken())
                        .addHeader("Content-type", "application/json")
                        .addHeader("Accept", "*/*") // fixme - this shouldn't be needed
                        .bodyString(data, ContentType.APPLICATION_JSON)
                        .execute().returnResponse();

                String payload = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
                logger.debug("Response: " + payload);
                if (response.getStatusLine().getStatusCode() >= 300) {
                    throw new HttpResponseException(response.getStatusLine().getStatusCode(),
                            response.getStatusLine().getReasonPhrase());
                }
                return payload;
            } catch (Exception e) {
                logger.error("Something unexpected happened: " + e.getMessage());
                TokenStore.delete(username); // fixme - needed only for 401
                throw new RuntimeException(e); // todo handle error - token revoked, etc
            }
        }
    }

    @RequestMapping(value = "/loop-template", method = RequestMethod.GET)
    @ResponseBody
    public String getLoopTemplates(@RequestParam(value = "profile_id", required = true) String profile_id) {

        Token token = TokenStore.get(username);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            try {
                HttpResponse response = Request.Get(getApiBaseUrl() + "/profile/" + profile_id + "/loop-template")
                        .addHeader("Authorization", "Bearer " + token.getAccessToken())
                        .addHeader("Content-type", "application/json")
                        .addHeader("Accept", "*/*") // fixme - this shouldn't be needed
                        .execute().returnResponse();

                String payload = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
                logger.debug("Response: " + payload);
                if (response.getStatusLine().getStatusCode() >= 300) {
                    throw new HttpResponseException(response.getStatusLine().getStatusCode(),
                            response.getStatusLine().getReasonPhrase());
                }
                return payload;
            } catch (Exception e) {
                logger.error("Something unexpected happened: " + e.getMessage());
                TokenStore.delete(username); // fixme - needed only for 401
                throw new RuntimeException(e); // todo handle error - token revoked, etc
            }
        }
    }

    @RequestMapping("/")
    public String home(HttpServletRequest request, Model model) {
//        User user = getUser();

        boolean connected = !StringUtils.isEmpty(TokenStore.get(username));



        model.addAttribute("connected", connected);
        model.addAttribute("authorize_url", getAuthorizeUrl());
        model.addAttribute("username", StringUtils.isEmpty(TokenStore.get(username)));

        if (connected) {
            model.addAttribute("profiles", getProfiles());
        }

        return "home";
    }

    @RequestMapping("/delete")
    @ResponseBody
    public void deleteToken() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        TokenStore.delete(user.getUsername());
    }

    @RequestMapping("/auth/callback")
    public String callback(HttpServletRequest request, @RequestParam String code) {

        // XSRF protection
//        String csrfToken = csrfTokenRepository.loadToken(request).getToken();
//        if (!state.equals(csrfToken)) {
//            throw new ForbiddenException("csrf failure.");
//        }

        // HTTP Basic Auth
        String authStr = Base64Utils.encodeToString((clientId + ":" + clientSecret).getBytes(Consts.UTF_8));
        try {
            Token token = getToken(code, authStr);
            TokenStore.save(username, token);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "callback";
    }

    private String getProfiles() {
        Token token = TokenStore.get(username);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            try {
                HttpResponse response = Request.Get(getApiBaseUrl() + "/profile")
                        .addHeader("Authorization", "Bearer " + token.getAccessToken())
                        .addHeader("Content-type", "application/json")
                        .addHeader("Accept", "*/*") // fixme - this shouldn't be needed
                        .execute().returnResponse();

                String payload = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
                logger.debug("Response: " + payload);
                if (response.getStatusLine().getStatusCode() >= 300) {
                    throw new HttpResponseException(response.getStatusLine().getStatusCode(),
                            response.getStatusLine().getReasonPhrase());
                }

                return payload;
            } catch (Exception e) {
                logger.error("Something unexpected happened: " + e.getMessage());
                TokenStore.delete(username); // fixme - needed only for 401
                throw new RuntimeException(e); // todo handle error - token revoked, etc
            }
        }
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public class ForbiddenException extends RuntimeException {
        public ForbiddenException(String msg) {
            super(msg);
        }
    }

    private String getAuthorizeUrl() {
        try {
            return new URIBuilder(oauthEndpoint + "/authorize")
                    .addParameter("response_type", "code")
                    .addParameter("client_id", clientId)
                    .addParameter("redirect_uri", redirectUrl).toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private String getTokenUrl() {
        return new StringBuilder(oauthEndpoint).append("/token").toString();
    }

    private User getUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    private Token getToken(@RequestParam String code, String authStr) throws IOException {
        String response = Request.Post(getTokenUrl())
                .addHeader("Authorization", "Basic " + authStr)
                .bodyForm(Form.form()
                        .add("code", code)
                        .add("grant_type", "authorization_code")
                        .add("redirect_uri", redirectUrl).build())
                .execute().returnContent().toString();

        logger.debug("Token response: {}", response);

        Gson gson = new Gson();
        return gson.fromJson(response, Token.class);
    }

    private String getApiBaseUrl() {
        return apiEndpoint;
    }

}