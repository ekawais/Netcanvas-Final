-- Create the NetCanvas database
CREATE DATABASE IF NOT EXISTS NetCanvas;

-- Switch to the NetCanvas database
USE NetCanvas;

-- Create the admin table
-- Create the admin table
CREATE TABLE IF NOT EXISTS admin (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    license_key VARCHAR(255),  -- Adding the license_key column
    isAdmin TINYINT NOT NULL DEFAULT 1
);

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);
-- Create the procedure for registering admins
DELIMITER //

CREATE PROCEDURE RegisterAdmin(
    IN p_name VARCHAR(255),
    IN p_email VARCHAR(255),
    IN p_password VARCHAR(255),
    IN p_license_key VARCHAR(255)
)
BEGIN
    DECLARE admin_count INT;

    -- Check if admin already exists
    SELECT COUNT(*) INTO admin_count FROM admin WHERE email = p_email;
    
    IF admin_count > 0 THEN
        SELECT 'Admin already exists.' AS message;
    ELSE
        -- Insert admin record
        INSERT INTO admin (name, email, password) VALUES (p_name, p_email, p_password);
        SELECT 'Admin registered successfully.' AS message;
    END IF;
END //

DELIMITER ;