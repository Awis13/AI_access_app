-- Database initialization script
-- Drops and recreates everything fresh on each start

-- Drop existing tables and sequences if they exist
DROP TABLE IF EXISTS "public"."user_role" CASCADE;
DROP TABLE IF EXISTS "public"."user" CASCADE;
DROP TABLE IF EXISTS "public"."role" CASCADE;
DROP SEQUENCE IF EXISTS hibernate_sequence CASCADE;

-- Create hibernate sequence for IDs
CREATE SEQUENCE hibernate_sequence START WITH 1000 INCREMENT BY 1;

-- Create roles table
CREATE TABLE IF NOT EXISTS "public"."role" (
    "id" BIGSERIAL PRIMARY KEY,
    "name" VARCHAR(255) NOT NULL,
    "description" VARCHAR(500),
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
INSERT INTO "public"."role" ("id", "name", "description") VALUES 
(1, 'USER', 'Standard user role'),
(2, 'ADMIN', 'Administrator role'),
(3, 'MANAGER', 'Manager role');

-- Create user table with all the fields from your application
CREATE TABLE IF NOT EXISTS "public"."user" (
    "id" BIGINT PRIMARY KEY DEFAULT nextval('hibernate_sequence'),
    "version" INTEGER DEFAULT 0,
    "login" VARCHAR(255) UNIQUE NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "password" VARCHAR(255) NOT NULL,
    "enabled" BOOLEAN DEFAULT true,
    "account_expired" BOOLEAN DEFAULT false,
    "account_locked" BOOLEAN DEFAULT false,
    "password_expired" BOOLEAN DEFAULT false,
    "email" VARCHAR(255) UNIQUE NOT NULL,
    "password_renew_hash" VARCHAR(255),
    "preferred_language" VARCHAR(2) DEFAULT 'CS',
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create user_role junction table
CREATE TABLE IF NOT EXISTS "public"."user_role" (
    "user_id" BIGINT NOT NULL REFERENCES "public"."user"("id") ON DELETE CASCADE,
    "role_id" BIGINT NOT NULL REFERENCES "public"."role"("id") ON DELETE CASCADE,
    PRIMARY KEY ("user_id", "role_id")
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_login ON "public"."user"("login");
CREATE INDEX IF NOT EXISTS idx_user_email ON "public"."user"("email");
CREATE INDEX IF NOT EXISTS idx_user_enabled ON "public"."user"("enabled");

-- Insert a test admin user (password: admin123)
INSERT INTO "public"."user" 
    ("id", "version", "login", "name", "password", "enabled", "account_expired", "account_locked", "password_expired", "email", "password_renew_hash", "preferred_language") 
VALUES 
    (nextval('hibernate_sequence'), 0, 'admin', 'System Administrator', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfWuYWaJsM0.FUC', true, false, false, false, 'admin@example.com', null, 'EN');

-- Assign admin role to the test user
INSERT INTO "public"."user_role" ("user_id", "role_id") 
SELECT u.id, 2 
FROM "public"."user" u 
WHERE u.login = 'admin';

-- Show created tables
SELECT 'Database initialized successfully' as status;
