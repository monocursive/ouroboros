//! The wire vocabulary: frames, error codes, and the handshake.
//!
//! Decoding is tolerant in one direction only. Unknown fields are ignored and an
//! unrecognized error code survives as [`ErrorCode::Other`], because the runtime this
//! client talks to rewrites its own modules and a client that refuses a payload it does
//! not fully recognize would go blind on the first capability someone forges. Result
//! payloads stay [`serde_json::Value`]: the gateway's encoding is a self-describing tree
//! by construction, and typing those trees belongs with the golden fixtures, not here.
//!
//! Encoding is not tolerant. Every request carries a numeric id and an object `params`,
//! because `Ouroboros.Gateway.Conn` refuses anything else and there is no reason for
//! this client to discover that at runtime.

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The only compatibility contract between this binary and a runtime.
pub const PROTOCOL: u32 = 1;

/// Every error the gateway names, plus the arm that keeps a newer server legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    Unauthenticated,
    ProtocolMismatch,
    ScopeDenied,
    Unavailable,
    UpstreamTimeout,
    UpstreamError,
    NotFound,
    Other(i64),
}

impl ErrorCode {
    pub fn from_i64(code: i64) -> Self {
        match code {
            -32700 => Self::ParseError,
            -32600 => Self::InvalidRequest,
            -32601 => Self::MethodNotFound,
            -32602 => Self::InvalidParams,
            -32001 => Self::Unauthenticated,
            -32002 => Self::ProtocolMismatch,
            -32003 => Self::ScopeDenied,
            -32004 => Self::Unavailable,
            -32005 => Self::UpstreamTimeout,
            -32006 => Self::UpstreamError,
            -32007 => Self::NotFound,
            other => Self::Other(other),
        }
    }

    pub fn as_i64(self) -> i64 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::Unauthenticated => -32001,
            Self::ProtocolMismatch => -32002,
            Self::ScopeDenied => -32003,
            Self::Unavailable => -32004,
            Self::UpstreamTimeout => -32005,
            Self::UpstreamError => -32006,
            Self::NotFound => -32007,
            Self::Other(code) => code,
        }
    }

    /// Whether reconnecting could plausibly answer differently. A rejected token and a
    /// protocol the server does not speak are decisions, not outages, so a client that
    /// retried them would spin against a server that is behaving correctly.
    pub fn is_handshake_refusal(self) -> bool {
        matches!(self, Self::Unauthenticated | Self::ProtocolMismatch)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ParseError => "parse_error",
            Self::InvalidRequest => "invalid_request",
            Self::MethodNotFound => "method_not_found",
            Self::InvalidParams => "invalid_params",
            Self::Unauthenticated => "unauthenticated",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::ScopeDenied => "scope_denied",
            Self::Unavailable => "unavailable",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamError => "upstream_error",
            Self::NotFound => "not_found",
            Self::Other(_) => "unknown",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.as_i64())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.as_i64())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_i64(i64::deserialize(deserializer)?))
    }
}

/// A JSON-RPC error object as the gateway builds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: ErrorCode,
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// The server protocol a `-32002` carries, which is the whole point of that error.
    pub fn server_protocol(&self) -> Option<u64> {
        self.data.as_ref()?.get("server_protocol")?.as_u64()
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// One outbound request. `params` is always an object because the gateway rejects any
/// other shape with `-32602`.
#[derive(Debug, Clone, Serialize)]
pub struct Request<'a> {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'a str,
    pub params: Value,
}

impl<'a> Request<'a> {
    pub fn new(id: u64, method: &'a str, params: Value) -> Self {
        let params = if params.is_object() {
            params
        } else {
            Value::Object(Default::default())
        };

        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

/// A server notification. Slice 3a routes these and consumes none of them.
#[derive(Debug, Clone)]
pub struct Notification {
    pub method: String,
    pub params: Value,
}

/// What one decoded inbound line turned out to be.
#[derive(Debug, Clone)]
pub enum Incoming {
    /// `id` is absent when the gateway answered a frame it could not correlate — a
    /// frame-level parse or shape refusal. This client only ever writes well-formed
    /// object frames with numeric ids, so an uncorrelatable answer is a contract break
    /// rather than a stray.
    Response {
        id: Option<u64>,
        outcome: Box<Result<Value, RpcError>>,
    },
    Notification(Notification),
    /// A frame that is neither. Ignored rather than fatal: a newer server may notify in
    /// shapes this build does not know.
    Unrecognized,
}

#[derive(Debug, Deserialize)]
struct RawFrame {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

impl Incoming {
    pub fn decode(line: &[u8]) -> Result<Self, serde_json::Error> {
        let frame: RawFrame = serde_json::from_slice(line)?;

        let has_id = matches!(&frame.id, Some(value) if !value.is_null());

        if let Some(method) = frame.method {
            if !has_id {
                return Ok(Self::Notification(Notification {
                    method,
                    params: frame.params.unwrap_or(Value::Null),
                }));
            }

            return Ok(Self::Unrecognized);
        }

        let id = frame.id.as_ref().and_then(Value::as_u64);

        match (frame.result, frame.error) {
            (_, Some(error)) => Ok(Self::Response {
                id,
                outcome: Box::new(Err(error)),
            }),
            (Some(result), None) => Ok(Self::Response {
                id,
                outcome: Box::new(Ok(result)),
            }),
            (None, None) => Ok(Self::Unrecognized),
        }
    }
}

/// What `hello` presents. The token is written here and nowhere else that outlives the
/// frame; see `transport::Secret`.
#[derive(Debug, Clone, Serialize)]
pub struct HelloParams<'a> {
    pub token: &'a str,
    pub protocol: u32,
    pub client: &'a str,
}

/// What `hello` answers. Every field defaults so that a server which grew or dropped one
/// stays connectable — the protocol integer is the compatibility contract, not the shape
/// of this map.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Hello {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub protocol: u32,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub methods: Vec<String>,
}

impl Hello {
    pub fn serves(&self, method: &str) -> bool {
        self.methods.iter().any(|name| name == method)
    }

    pub fn operates(&self) -> bool {
        self.scope == "operate"
    }
}

/// The name this client presents in `hello`, truncated by the server at 120 bytes.
pub fn client_name() -> String {
    format!("ouro {}", env!("CARGO_PKG_VERSION"))
}
