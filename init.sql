CREATE DATABASE IF NOT EXISTS appdb;

-- Create basic users
CREATE USER 'user_no_ssl'@'%' IDENTIFIED WITH mysql_native_password BY 'pass_no_ssl';
CREATE USER 'user_with_ssl'@'%' IDENTIFIED WITH mysql_native_password BY 'pass_with_ssl';

-- Grant privileges
GRANT ALL PRIVILEGES ON appdb.* TO 'user_no_ssl'@'%';
GRANT ALL PRIVILEGES ON appdb.* TO 'user_with_ssl'@'%';

CREATE USER 'spiffe_user'@'%' IDENTIFIED WITH mysql_native_password BY 'spiffe_password';
GRANT ALL PRIVILEGES ON appdb.* TO 'spiffe_user'@'%';

FLUSH PRIVILEGES;
