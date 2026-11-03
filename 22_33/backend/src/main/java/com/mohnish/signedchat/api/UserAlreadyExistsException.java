package com.mohnish.signedchat.api;

public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String name) {
        super("User '" + name + "' already exists");
    }
}
