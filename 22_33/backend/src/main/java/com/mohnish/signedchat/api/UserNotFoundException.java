package com.mohnish.signedchat.api;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String name) {
        super("User '" + name + "' does not exist");
    }
}
