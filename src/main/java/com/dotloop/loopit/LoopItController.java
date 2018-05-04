package com.dotloop.loopit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
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

    private String USERNAME = "api user";

    private Request attachHeaders(Request request) {
        Token token = TokenStore.get(USERNAME);
        request.addHeader("Authorization", "Bearer " + token.getAccessToken())
                .addHeader("Content-type", ContentType.APPLICATION_JSON.toString());

        return request;
    }

    private Request attachBody(Request request,  String bodyData) {
        request.bodyString(bodyData, ContentType.APPLICATION_JSON);

        return request;
    }

    private String makeRequest(String type, String params, String bodyData) throws Exception {
        try {
            params = params.isEmpty() ? "" : params;

            Request request = attachHeaders(Request.Get(getApiBaseUrl() + params));

            if (type.equalsIgnoreCase("post")) {
                request = attachBody(attachHeaders(Request.Post(getApiBaseUrl() + params)), bodyData);
            }

            HttpResponse response = request.execute().returnResponse();

            String payload = IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            logger.debug("Response: " + payload);
            if (response.getStatusLine().getStatusCode() >= 300) {
                throw new HttpResponseException(response.getStatusLine().getStatusCode(),
                        response.getStatusLine().getReasonPhrase());
            }

            return payload;

        } catch (Exception e) {
            logger.error("Something unexpected happened: " + e.getMessage());
            TokenStore.delete(USERNAME); // fixme - needed only for 401
            throw new RuntimeException(e); // todo handle error - token revoked, etc
        }

    }

    private String makeRequest(String type, String params) throws Exception {
        return makeRequest(type, params, "");
    }

    @RequestMapping(value = "/loopit", method = RequestMethod.POST)
    @ResponseBody
    public String loopIt(
            @RequestParam(value = "profile_id", required = true) String profile_id,
            @RequestBody Loop loop) throws Exception {

        Token token = TokenStore.get(USERNAME);

        ObjectMapper mapper = new ObjectMapper();
        String data = mapper.writeValueAsString(loop);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            return makeRequest("post", "/loop-it?profile_id=" + profile_id, data);
        }
    }

    @RequestMapping(value = "/loop-template", method = RequestMethod.GET)
    @ResponseBody
    public String getLoopTemplates(@RequestParam(value = "profile_id", required = true) String profile_id) throws Exception {
        Token token = TokenStore.get(USERNAME);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            return makeRequest("get", "/profile/" + profile_id + "/loop-template");
        }
    }

    @RequestMapping("/")
    public String home(HttpServletRequest request, Model model) throws Exception {
        boolean connected = !StringUtils.isEmpty(TokenStore.get(USERNAME));

        model.addAttribute("connected", connected);
        model.addAttribute("authorize_url", getAuthorizeUrl());
        model.addAttribute("username", StringUtils.isEmpty(TokenStore.get(USERNAME)));

        if (connected) {
            model.addAttribute("profiles", getProfiles());
            String folders = getFolders();
            System.out.println("");
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
        // HTTP Basic Auth
        String authStr = Base64Utils.encodeToString((clientId + ":" + clientSecret).getBytes(Consts.UTF_8));
        try {
            Token token = getToken(code, authStr);
            TokenStore.save(USERNAME, token);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "callback";
    }

    private String getProfiles() throws Exception {
        Token token = TokenStore.get(USERNAME);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            return makeRequest("get", "/profile");
        }
    }

    private String getFolders() throws Exception {
        Token token = TokenStore.get(USERNAME);

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            return makeRequest("get", "/profile/4885868/loop/79983228/folder?include_documents=true");
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