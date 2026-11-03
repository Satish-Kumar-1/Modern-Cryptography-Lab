package com.mohnish.signedchat;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "app.cors.allowed-origin=https://signedchat-messaging-lab.freerhea16.chatgpt.site")
@AutoConfigureMockMvc
class CorsApiTests {
    @Autowired MockMvc mvc;

    @Test
    void hostedFrontendCanPreflightJsonMessages() throws Exception {
        mvc.perform(options("/api/messages")
            .header("Origin", "https://signedchat-messaging-lab.freerhea16.chatgpt.site")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://signedchat-messaging-lab.freerhea16.chatgpt.site"));
    }

    @Test
    void unconfiguredOriginIsRejected() throws Exception {
        mvc.perform(options("/api/messages")
            .header("Origin", "https://untrusted.example")
            .header("Access-Control-Request-Method", "POST"))
            .andExpect(status().isForbidden())
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
