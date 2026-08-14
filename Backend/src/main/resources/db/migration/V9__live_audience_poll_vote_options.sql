-- Multi-select poll support: each vote row keeps one entry per selected option
-- in a separate collection table, so the existing (poll_id, user_id) uniqueness
-- still enforces "one vote row per user per poll" while allowing several options.
CREATE TABLE IF NOT EXISTS live_audience_poll_vote_options (
    poll_vote_id BIGINT       NOT NULL,
    option_text  VARCHAR(200) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lapv_options_poll_vote_id
    ON live_audience_poll_vote_options(poll_vote_id);
