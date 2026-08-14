package com.sandeep.eventrabackend.event;

/**
 * Published after an event's cancellation DB transaction commits, carrying
 * the data needed to run side effects (refunds, notifications) outside the
 * transaction (#17831).
 */
public record EventCancelledEvent(Long eventId, String reason) {
}
