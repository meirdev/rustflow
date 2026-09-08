-- Arroyo pipeline: read the JSON flows Vector produces, aggregate them into
-- sliding top-talker windows, and write the results back to Kafka.
--
-- A NetFlow/IPFIX record arrives when a flow expires and covers everything
-- since the exporter's previous report (up to its active timeout, typically
-- 60 s), so a short tumbling window would bucket a minute of traffic wherever
-- the record happened to land. A hopping window 60 s wide that slides every
-- 10 s gives a fresh answer every 10 s over a lookback at least as long as
-- the active timeout. Windows overlap, so rows must not be summed across
-- windows; each flow is counted in width/slide = 6 of them.

CREATE TABLE flows (
    time_received   TIMESTAMP,
    flow_type       TEXT,
    sampler_address TEXT,
    src_addr        TEXT,
    dst_addr        TEXT,
    src_port        INT,
    dst_port        INT,
    proto           INT,
    bytes           BIGINT,
    packets         BIGINT,
    sampling_rate   INT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'kafka:9092',
    topic = 'flows',
    type = 'source',
    format = 'json',
    'source.offset' = 'earliest'
);

CREATE TABLE flow_stats (
    window_start TIMESTAMP,
    window_end   TIMESTAMP,
    src_addr     TEXT,
    dst_addr     TEXT,
    proto        INT,
    flows        BIGINT,
    bytes        BIGINT,
    packets      BIGINT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'kafka:9092',
    topic = 'flow-stats',
    type = 'sink',
    format = 'json'
);

INSERT INTO flow_stats
SELECT
    window.start AS window_start,
    window.end   AS window_end,
    src_addr,
    dst_addr,
    proto,
    flows,
    bytes,
    packets
FROM (
    SELECT
        HOP(INTERVAL '10 seconds', INTERVAL '60 seconds') AS window, -- (slide, width)
        src_addr,
        dst_addr,
        proto,
        COUNT(*)     AS flows,
        SUM(bytes)   AS bytes,
        SUM(packets) AS packets
    FROM flows
    GROUP BY window, src_addr, dst_addr, proto
);
