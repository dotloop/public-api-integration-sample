package com.dotloop.loopit;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TokenStore {

    private final static Map<String, Token> tokens = new ConcurrentHashMap<>();

    public static Token get(String username) {
        return tokens.get(username);
    }

    public static void delete(String username) {
        tokens.remove(username);
    }

    public static void save(String username, Token token) {
        tokens.put(username, token);
    }
}
