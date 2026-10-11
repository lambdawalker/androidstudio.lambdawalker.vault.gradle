# Broker protocol v1

Transport: private local Windows named pipe, one request and one response, 60-second maximum lifetime. All integers are signed 32-bit big-endian. A frame is a byte count in 1..65536 followed by exactly that many bytes. Each UTF-8 field has a byte length in 0..16384. Reject malformed UTF-8, oversized values and trailing frame bytes.

Request frame: version = 1, then capability, canonical project path, module, variant, identity ID, build ID. Capability is 43 URL-safe base64 characters. The server binds and consumes it once for this exact target.

Response: boolean byte 0 means failure with no diagnostic text. Byte 1 precedes a frame containing identity count = 1, then ID, canonical keystore path, store type (JKS or PKCS12), alias, lowercase SHA-256 certificate fingerprint, store password, key password. Client verifies the identity and wipes mutable password buffers after use. Client sends acknowledgement byte 1 after reading the response. No secrets belong in logs or error messages.

The tests in both repositories use the same independently encoded request/response vectors. Keep them identical; an incompatible format requires a new version. Passwords in vectors are disposable test values.
