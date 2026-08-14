package com.sandeep.eventrabackend.controller;

import com.sandeep.eventrabackend.model.Event;
import com.sandeep.eventrabackend.model.Role;
import com.sandeep.eventrabackend.model.User;
import com.sandeep.eventrabackend.repository.EventRepository;
import com.sandeep.eventrabackend.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Issue #17843 — subtitle session lifecycle endpoints must enforce
 * object-level authorization. Only the event organizer (or an admin) may
 * start, end, read or enumerate a live caption session; any other
 * authenticated user gets 403.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SubtitleSessionAccessControlTests {

    private static final String SUBTITLES = "/api/v1/subtitles";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EventRepository eventRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Long eventId;
    private final String organizerEmail = "suborganizer@example.com";
    private final String attackerEmail = "subattacker@example.com";

    @BeforeEach
    void setUp() {
        eventRepository.deleteAll();
        userRepository.deleteAll();

        User organizer = userRepository.save(User.builder()
                .firstName("Sub")
                .lastName("Organizer")
                .email(organizerEmail)
                .username("suborganizer")
                .password(passwordEncoder.encode("password"))
                .role(Role.CLIENT)
                .build());

        userRepository.save(User.builder()
                .firstName("Sub")
                .lastName("Attacker")
                .email(attackerEmail)
                .username("subattacker")
                .password(passwordEncoder.encode("password"))
                .role(Role.CLIENT)
                .build());

        Event event = new Event();
        event.setTitle("Subtitle Session Access Test Event");
        event.setCapacity(50);
        event.setEventDate(LocalDateTime.now().plusDays(10));
        event.setOwnerId(organizer.getId());
        event.setPublic(true);
        eventId = eventRepository.save(event).getId();
    }

    @Test
    @DisplayName("Non-organizer cannot start or enumerate sessions for an event (403)")
    void attackerCannotStartOrListSessions() throws Exception {
        mockMvc.perform(post(SUBTITLES + "/session/start")
                        .with(user(attackerEmail))
                        .param("eventId", String.valueOf(eventId)))
                .andExpect(status().isForbidden());

        mockMvc.perform(post(SUBTITLES + "/session/attacker-session/start")
                        .with(user(attackerEmail))
                        .param("eventId", String.valueOf(eventId)))
                .andExpect(status().isForbidden());

        mockMvc.perform(get(SUBTITLES + "/event/{eventId}/sessions", eventId)
                        .with(user(attackerEmail)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Non-organizer cannot read or end an organizer's live session (403)")
    void attackerCannotReadOrEndSessions() throws Exception {
        String sessionId = "organizer-live-session";
        mockMvc.perform(post(SUBTITLES + "/session/{sessionId}/start", sessionId)
                        .with(user(organizerEmail))
                        .param("eventId", String.valueOf(eventId)))
                .andExpect(status().isCreated());

        mockMvc.perform(get(SUBTITLES + "/session/{sessionId}", sessionId)
                        .with(user(attackerEmail)))
                .andExpect(status().isForbidden());

        mockMvc.perform(post(SUBTITLES + "/session/{sessionId}/end", sessionId)
                        .with(user(attackerEmail)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Event organizer can start, read, list and end their own sessions")
    void organizerCanManageOwnSessions() throws Exception {
        mockMvc.perform(post(SUBTITLES + "/session/start")
                        .with(user(organizerEmail))
                        .param("eventId", String.valueOf(eventId)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventId").value(eventId.intValue()));

        String sessionId = "organizer-managed-session";
        mockMvc.perform(post(SUBTITLES + "/session/{sessionId}/start", sessionId)
                        .with(user(organizerEmail))
                        .param("eventId", String.valueOf(eventId)))
                .andExpect(status().isCreated());

        mockMvc.perform(get(SUBTITLES + "/session/{sessionId}", sessionId)
                        .with(user(organizerEmail)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessionId").value(sessionId));

        mockMvc.perform(get(SUBTITLES + "/event/{eventId}/sessions", eventId)
                        .with(user(organizerEmail)))
                .andExpect(status().isOk());

        mockMvc.perform(post(SUBTITLES + "/session/{sessionId}/end", sessionId)
                        .with(user(organizerEmail)))
                .andExpect(status().isOk());
    }
}
