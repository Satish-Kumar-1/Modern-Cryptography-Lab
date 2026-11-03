package com.mohnish.signedchat.api.dto;

import jakarta.validation.constraints.NotBlank;

/** {@code trusted} defaults to true when omitted. */
public record CreateUserRequest(@NotBlank String name, Boolean trusted) {
    public boolean isTrusted() {
        return trusted == null || trusted;
    }
}
