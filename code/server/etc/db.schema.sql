
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_device TEXT NOT NULL,
    recipient_device TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW()
);

