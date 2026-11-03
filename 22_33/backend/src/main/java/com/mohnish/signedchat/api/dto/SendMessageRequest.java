package com.mohnish.signedchat.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Content may be whitespace-only (it is signed verbatim) but not null. */
public record SendMessageRequest(
    @NotBlank String sender,
    @NotBlank String recipient,
    @NotNull String content
) {}
