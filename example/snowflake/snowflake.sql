-- Create a database
CREATE DATABASE GOCI;

-- Create a role for Gateway CI
CREATE ROLE GATEWAY_CI_ROLE;

-- Create a user
CREATE USER GATEWAYCI
    PASSWORD = 'StrongPassword123'
    DEFAULT_ROLE = GATEWAY_CI_ROLE;

-- Grant admin privileges to the user
GRANT ROLE ACCOUNTADMIN TO USER GATEWAYCI;

-- Grant database privileges
GRANT ALL ON DATABASE GOCI TO ROLE GATEWAY_CI_ROLE;

-- Grant usage on all existing schemas
GRANT USAGE ON ALL SCHEMAS IN DATABASE GOCI TO ROLE GATEWAY_CI_ROLE;

-- Grant usage on future schemas
GRANT USAGE ON FUTURE SCHEMAS IN DATABASE GOCI TO ROLE GATEWAY_CI_ROLE;

-- Use the created database
USE GOCI;

-- Create a test table
CREATE OR REPLACE TABLE employees (
    employee_id INT AUTOINCREMENT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    department VARCHAR(50),
    salary DECIMAL(10, 2),
    hire_date DATE
);

-- Insert sample data
INSERT INTO employees (first_name, last_name, email, department, salary, hire_date)
VALUES 
    ('John', 'Doe', 'john.doe@example.com', 'Sales', 75000.00, '2021-03-15'),
    ('Jane', 'Smith', 'jane.smith@example.com', 'Marketing', 85000.00, '2020-07-22'),
    ('Mike', 'Johnson', 'mike.johnson@example.com', 'IT', 95000.00, '2019-11-05'),
    ('Emily', 'Brown', 'emily.brown@example.com', 'HR', 65000.00, '2022-01-10'),
    ('David', 'Wilson', 'david.wilson@example.com', 'Finance', 88000.00, '2020-05-18');

-- Verify data insertion
SELECT * FROM employees;

-- Create additional test table
CREATE OR REPLACE TABLE departments (
    department_id INT AUTOINCREMENT PRIMARY KEY,
    department_name VARCHAR(50),
    location VARCHAR(100)
);

-- Insert department data
INSERT INTO departments (department_name, location)
VALUES 
    ('Sales', 'New York'),
    ('Marketing', 'San Francisco'),
    ('IT', 'Seattle'),
    ('HR', 'Chicago'),
    ('Finance', 'Boston');

-- Verify department data
SELECT * FROM GOCI.PUBLIC.DEPARTMENTS;

-- Grant additional privileges on tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA GOCI.PUBLIC TO ROLE GATEWAY_CI_ROLE;
GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE TABLES IN SCHEMA GOCI.PUBLIC TO ROLE GATEWAY_CI_ROLE;