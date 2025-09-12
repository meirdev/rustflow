use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum HttpMethod {
    Other = 0,
    Options = 1,
    Get = 2,
    Head = 3,
    Post = 4,
    Put = 5,
    Delete = 6,
    Trace = 7,
    Connect = 8,
}

pub type Version = u32;

/// HTTP request
#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    /// method
    pub method: HttpMethod,
    /// HTTP protocol version
    pub protocol: Version,
    /// URI exactly as it came from the client
    pub uri: String, // 255
    /// Host value from request header
    pub host: String, // 64
    /// Referer value from request header
    pub referer: String, // 255
    /// User-Agent value from request header
    pub useragent: String, // 128
    /// X-Forwarded-For value from request header
    pub xff: String, // 64
    /// RFC 1413 identity of user
    pub authuser: String, // 32
    /// Mime-Type of response
    pub mime_type: String, // 64
    /// Content-Length of request
    pub req_bytes: u64,
    /// Content-Length of response
    pub resp_bytes: u64,
    /// Duration of the operation (in microseconds)
    pub duration_us: u32,
    /// HTTP status code
    pub status: i32,
}

/// Extended proxy request
#[derive(Debug, Clone, Serialize)]
pub struct ExtendedProxyRequest {
    /// URI in request to downstream server
    pub uri: String, // 255
    /// Host in request to downstream server
    pub host: String, // 64
}

/// HTTP counters
#[derive(Debug, Clone, Serialize)]
pub struct HttpCounters {
    pub method_option_count: u32,
    pub method_get_count: u32,
    pub method_head_count: u32,
    pub method_post_count: u32,
    pub method_put_count: u32,
    pub method_delete_count: u32,
    pub method_trace_count: u32,
    pub method_connect_count: u32,
    pub method_other_count: u32,
    pub status_1xx_count: u32,
    pub status_2xx_count: u32,
    pub status_3xx_count: u32,
    pub status_4xx_count: u32,
    pub status_5xx_count: u32,
    pub status_other_count: u32,
}
