package com.mohnish.signedchat.api;

import com.mohnish.signedchat.api.dto.CreateUserRequest;
import com.mohnish.signedchat.api.dto.CreatedUserResponse;
import com.mohnish.signedchat.api.dto.ReceiveResponse;
import com.mohnish.signedchat.api.dto.SignedMessageDto;
import com.mohnish.signedchat.api.dto.UserResponse;
import com.mohnish.signedchat.api.dto.UserKeysResponse;
import com.mohnish.signedchat.model.ChatUser;
import com.mohnish.signedchat.service.MessagingService;
import com.mohnish.signedchat.service.UserService;
import jakarta.validation.Valid;
import java.security.GeneralSecurityException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService users;
    private final MessagingService messaging;

    public UserController(UserService users, MessagingService messaging) {
        this.users = users;
        this.messaging = messaging;
    }

    @PostMapping
    public ResponseEntity<CreatedUserResponse> create(
        @Valid @RequestBody CreateUserRequest request
    ) throws GeneralSecurityException {
        ChatUser user = users.create(request.name(), request.isTrusted());
        return ResponseEntity.created(
            UriComponentsBuilder.fromPath("/api/users").pathSegment(user.getName()).build().encode().toUri()
        ).cacheControl(CacheControl.noStore())
         .body(CreatedUserResponse.of(user, users.isTrusted(user.getName())));
    }

    @GetMapping
    public List<UserResponse> list() {
        return users
            .list()
            .stream()
            .map(u -> UserResponse.of(u, users.isTrusted(u.getName())))
            .toList();
    }

    @GetMapping("/{name}")
    public UserResponse get(@PathVariable String name) {
        return UserResponse.of(users.get(name), users.isTrusted(name));
    }

    /** Demo lookup only: knowing a username is not authentication. */
    @GetMapping("/{username}/keys")
    public ResponseEntity<UserKeysResponse> keys(@PathVariable String username) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
            .body(UserKeysResponse.of(users.get(username), users.isTrusted(username)));
    }

    /** Verifies the signed message and, if valid, delivers it to the inbox. */
    @PostMapping("/{name}/inbox")
    public ResponseEntity<ReceiveResponse> receive(
        @PathVariable String name,
        @Valid @RequestBody SignedMessageDto body
    ) throws GeneralSecurityException {
        users.get(name);
        boolean accepted = messaging.receive(body.toDomain(), name);
        return ResponseEntity.status(
            accepted ? HttpStatus.CREATED : HttpStatus.UNPROCESSABLE_ENTITY
        ).body(new ReceiveResponse(accepted));
    }

    @GetMapping("/{name}/inbox")
    public List<SignedMessageDto> inbox(@PathVariable String name) {
        users.get(name);
        return messaging
            .getInbox(name)
            .stream()
            .map(SignedMessageDto::of)
            .toList();
    }
}
