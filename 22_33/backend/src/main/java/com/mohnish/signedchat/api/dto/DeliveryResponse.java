package com.mohnish.signedchat.api.dto;

public record DeliveryResponse(SignedMessageDto message, boolean delivered) {}
