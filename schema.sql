-- Run once against the "brickshare" database:  psql -U postgres -d brickshare -f schema.sql

-- pgcrypto gives us crypt() / gen_salt() for password hashing
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Login accounts (passwords are stored as bcrypt hashes, never as plain text)
CREATE TABLE IF NOT EXISTS users (
    user_id       SERIAL PRIMARY KEY,
    username      VARCHAR(50) NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Employee records shown in the table on the page
CREATE TABLE IF NOT EXISTS employees (
    employee_id SERIAL PRIMARY KEY,
    name        VARCHAR(50)   NOT NULL,
    surname     VARCHAR(50)   NOT NULL,
    dob         DATE          NOT NULL CHECK (dob <= CURRENT_DATE),
    gender      VARCHAR(10)   NOT NULL CHECK (gender IN ('Male', 'Female', 'Other')),
    salary      NUMERIC(12,2) NOT NULL CHECK (salary >= 0),
    designation VARCHAR(100)  NOT NULL
);
