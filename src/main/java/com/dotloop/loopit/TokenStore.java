package com.dotloop.loopit;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenStore {

    private Token token;

    public Token getToken() {
        return token;
    }

    public void save(Token token) {
        this.token = token;
    }
}
