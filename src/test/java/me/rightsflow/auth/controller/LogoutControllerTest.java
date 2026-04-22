package me.rightsflow.auth.controller;

import me.rightsflow.auth.config.TestSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {AuthController.class})
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
@DisplayName("LogoutController")
public class LogoutControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"})
    public void testLogoutGet() throws Exception {
        mockMvc.perform(get("/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/auth/login?logout=true"));
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"})
    public void testLogoutPost() throws Exception {
        mockMvc.perform(post("/logout").with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/auth/login?logout=true"));
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"})
    public void testLogoutWithRedirectUri() throws Exception {
        mockMvc.perform(get("/logout").param("redirect_uri", "/custom-page"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/custom-page"));
    }

}


