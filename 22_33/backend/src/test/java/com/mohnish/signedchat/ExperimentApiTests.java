package com.mohnish.signedchat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import com.jayway.jsonpath.JsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ExperimentApiTests {
    @Autowired MockMvc mvc;
    private String postJson(String path, String json) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }
    @Test void manualHttpWorkflowRejectsReplayAndTampering() throws Exception {
        String created = postJson("/api/labs", "{}");
        String id = JsonPath.read(created, "$.sessionId");
        String secret = JsonPath.read(created, "$.identities[0].privateKey");
        String base = "/api/labs/" + id;
        String draft = postJson(base + "/prepare", "{\"senderId\":\"alice\",\"receiverId\":\"bob\",\"message\":\"pay 10\"}");
        String packet = postJson(base + "/sign", "{\"packet\":" + draft + ",\"privateKey\":\"" + secret + "\"}");
        String delivery = "{\"packet\":" + packet + ",\"recipientId\":\"bob\",\"replayProtection\":true}";
        mvc.perform(post(base + "/deliver").contentType(MediaType.APPLICATION_JSON).content(delivery))
            .andExpect(status().isOk()).andExpect(jsonPath("$.accepted").value(true));
        mvc.perform(post(base + "/deliver").contentType(MediaType.APPLICATION_JSON).content(delivery))
            .andExpect(status().isOk()).andExpect(jsonPath("$.signatureValid").value(true))
            .andExpect(jsonPath("$.accepted").value(false)).andExpect(jsonPath("$.reason").value("DUPLICATE_MESSAGE_ID"));
        mvc.perform(post(base + "/deliver").contentType(MediaType.APPLICATION_JSON).content(delivery.replace("pay 10", "pay 9999")))
            .andExpect(status().isOk()).andExpect(jsonPath("$.signatureValid").value(false));
        mvc.perform(post(base + "/sign").contentType(MediaType.APPLICATION_JSON).content("{\"packet\":null,\"privateKey\":\"broken\"}"))
            .andExpect(status().isBadRequest());
        mvc.perform(delete(base)).andExpect(status().isOk());
        mvc.perform(get(base)).andExpect(status().isBadRequest());
    }
}
