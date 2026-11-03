package com.mohnish.signedchat.api;

import com.mohnish.signedchat.api.dto.DeliveryResponse;
import com.mohnish.signedchat.api.dto.SendMessageRequest;
import com.mohnish.signedchat.api.dto.SignedMessageDto;
import com.mohnish.signedchat.model.SignedMessage;
import com.mohnish.signedchat.service.MessagingService;
import com.mohnish.signedchat.service.UserService;
import jakarta.validation.Valid;
import java.security.GeneralSecurityException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private final UserService users;
    private final MessagingService messaging;

    public MessageController(UserService users, MessagingService messaging) {
        this.users = users;
        this.messaging = messaging;
    }

    /** Signs a message with the sender's private key without delivering it. */
    @PostMapping("/sign")
    public SignedMessageDto sign(@Valid @RequestBody SendMessageRequest request)
        throws GeneralSecurityException {
        return SignedMessageDto.of(
            messaging.send(
                users.get(request.sender()),
                request.recipient(),
                request.content()
            )
        );
    }

    /** Signs a message and delivers it to the recipient's inbox in one step. */
    @PostMapping
    public ResponseEntity<DeliveryResponse> send(
        @Valid @RequestBody SendMessageRequest request
    ) throws GeneralSecurityException {
        users.get(request.recipient());
        SignedMessage signed = messaging.send(
            users.get(request.sender()),
            request.recipient(),
            request.content()
        );
        boolean delivered = messaging.receive(signed, request.recipient());
        return ResponseEntity.status(
            delivered ? HttpStatus.CREATED : HttpStatus.UNPROCESSABLE_ENTITY
        ).body(new DeliveryResponse(SignedMessageDto.of(signed), delivered));
    }
}
