package com.dotloop.loopit;

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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

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

    @RequestMapping("/loopit")
    @ResponseBody
    public String loopIt() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        Token token = TokenStore.get(user.getUsername());

        if (token == null) {
            throw new AccessNotGrantedException();
        } else {
            logger.debug("Retrieved token : {}", token);

            try {
                HttpResponse response = Request.Post(getApiBaseUrl() + "/loop-it")
                        .addHeader("Authorization", "Bearer " + token.getAccessToken())
                        .addHeader("Content-type", "application/json")
                        .addHeader("Accept", "*/*") // fixme - this shouldn't be needed
                        .bodyString("{\"name\":\"Loop It Demo - " + new Date() + "\",\"transactionType\":\"PURCHASE_OFFER\",\"status\":\"PRE_OFFER\",\"streetName\":\"Waterview Dr\",\"streetNumber\":\"2100\",\"unit\":\"12\",\"city\":\"San Francisco\",\"zipCode\":\"94114\",\"state\":\"CA\",\"country\":\"US\",\"participants\":[{\"fullName\":\"Brian Erwin\",\"email\":\"brianerwin@newkyhome.com\",\"role\":\"BUYER\"},{\"fullName\":\"Allen Agent\",\"email\":\"allen.agent@gmail.com\",\"role\":\"LISTING_AGENT\"},{\"fullName\":\"Sean Seller\",\"email\":\"sean.seller@yahoo.com\",\"role\":\"SELLER\"}]}", ContentType.APPLICATION_JSON)
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
                TokenStore.delete(user.getUsername()); // fixme - needed only for 401
                throw new RuntimeException(e); // todo handle error - token revoked, etc
            }
        }
    }

    @RequestMapping("/hello")
    public String hello(HttpServletRequest request, Model model) {
        User user = getUser();

        boolean connected = !StringUtils.isEmpty(TokenStore.get(user.getUsername()));

        model.addAttribute("connected", connected);
        model.addAttribute("authorize_url", getAuthorizeUrl(csrfTokenRepository.loadToken(request).getToken()));
        model.addAttribute("username", StringUtils.isEmpty(TokenStore.get(user.getUsername())));

        return "hello";
    }

    @RequestMapping("/delete")
    @ResponseBody
    public void deleteToken() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        TokenStore.delete(user.getUsername());
    }

    @RequestMapping("/auth/callback")
    public String callback(HttpServletRequest request, @RequestParam String code, @RequestParam String state) {

        // XSRF protection
        String csrfToken = csrfTokenRepository.loadToken(request).getToken();
        if (!state.equals(csrfToken)) {
            throw new ForbiddenException("csrf failure.");
        }

        // HTTP Basic Auth
        String authStr = Base64Utils.encodeToString((clientId + ":" + clientSecret).getBytes(Consts.UTF_8));
        try {
            Token token = getToken(code, authStr);
            TokenStore.save(getUser().getUsername(), token);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "callback";
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public class ForbiddenException extends RuntimeException {
        public ForbiddenException(String msg) {
            super(msg);
        }
    }

    private String getAuthorizeUrl(String state) {
        try {
            return new URIBuilder(oauthEndpoint + "/authorize")
                    .addParameter("response_type", "code")
                    .addParameter("client_id", clientId)
                    .addParameter("redirect_uri", redirectUrl)
                    .addParameter("state", state).toString();
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