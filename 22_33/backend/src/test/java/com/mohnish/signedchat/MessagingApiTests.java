package com.mohnish.signedchat;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class MessagingApiTests {

    @Autowired
    MockMvc mvc;

    private void createUser(String name, boolean trusted) throws Exception {
        mvc
            .perform(
                post("/api/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        "{\"name\":\"" + name + "\",\"trusted\":" + trusted + "}"
                    )
            )
            .andExpect(status().isCreated());
    }

    private String json(String sender, String recipient, String content) {
        return (
            "{\"sender\":\"" + sender + "\",\"recipient\":\"" + recipient +
            "\",\"content\":\"" + content + "\"}"
        );
    }

    @Test
    void signedMessageIsDeliveredToInbox() throws Exception {
        createUser("alice1", true);
        createUser("bob1", true);

        mvc
            .perform(
                post("/api/messages")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json("alice1", "bob1", "hello"))
            )
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.delivered", is(true)));

        mvc
            .perform(get("/api/users/bob1/inbox"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(1)))
            .andExpect(jsonPath("$[0].message", is("hello")))
            .andExpect(jsonPath("$[0].senderId", is("alice1")));
    }

    @Test
    void messageFromUntrustedSenderIsRejected() throws Exception {
        createUser("bob2", true);
        createUser("mallory2", false);

        mvc
            .perform(
                post("/api/messages")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json("mallory2", "bob2", "hi"))
            )
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.delivered", is(false)));

        mvc
            .perform(get("/api/users/bob2/inbox"))
            .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void tamperedContentIsRejectedOnReceive() throws Exception {
        createUser("alice3", true);
        createUser("bob3", true);

        String signed = mvc
            .perform(
                post("/api/messages/sign")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json("alice3", "bob3", "pay 10"))
            )
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

        mvc
            .perform(
                post("/api/users/bob3/inbox")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(signed.replace("pay 10", "pay 9999"))
            )
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.accepted", is(false)));

        mvc
            .perform(
                post("/api/users/bob3/inbox")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(signed)
            )
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.accepted", is(true)));
    }

    @Test
    void errorsMapToHttpStatuses() throws Exception {
        createUser("dup", true);
        mvc
            .perform(
                post("/api/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"name\":\"dup\"}")
            )
            .andExpect(status().isConflict());
        mvc.perform(get("/api/users/nobody")).andExpect(status().isNotFound());
        mvc
            .perform(
                post("/api/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"name\":\" \"}")
            )
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errors.name").exists());
        mvc
            .perform(
                post("/api/users/dup/inbox")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        "{\"message\":\"x\",\"signature\":\"!!notbase64\",\"senderId\":\"dup\",\"receiverId\":\"dup\"}"
                    )
            )
            .andExpect(status().isBadRequest());
    }
    @Test
    void exactReplayIsRejectedButNewSigningOfSameTextIsAccepted() throws Exception {
        createUser("nonceAlice", true);
        createUser("nonceBob", true);
        String request = json("nonceAlice", "nonceBob", "same text");
        String first = mvc.perform(post("/api/messages/sign").contentType(MediaType.APPLICATION_JSON).content(request))
            .andExpect(status().isOk()).andExpect(jsonPath("$.nonce").isNotEmpty())
            .andReturn().getResponse().getContentAsString();
        mvc.perform(post("/api/users/nonceBob/inbox").contentType(MediaType.APPLICATION_JSON).content(first))
            .andExpect(status().isCreated());
        mvc.perform(post("/api/users/nonceBob/inbox").contentType(MediaType.APPLICATION_JSON).content(first))
            .andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$.accepted", is(false)));
        mvc.perform(post("/api/messages").contentType(MediaType.APPLICATION_JSON).content(request))
            .andExpect(status().isCreated()).andExpect(jsonPath("$.delivered", is(true)));
        mvc.perform(get("/api/users/nonceBob/inbox")).andExpect(jsonPath("$", hasSize(2)));
    }

}
