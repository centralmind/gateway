-- Create tables for endpoint integration tests
CREATE TABLE IF NOT EXISTS departments (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    budget DECIMAL(10, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS employees (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    department VARCHAR(100) NOT NULL,
    salary DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test departments
INSERT INTO departments (name, budget) VALUES
    ('Engineering', 500000.00),
    ('Sales', 300000.00),
    ('Marketing', 200000.00),
    ('HR', 150000.00),
    ('Finance', 250000.00);

-- Insert test employees
INSERT INTO employees (name, email, department, salary, created_at) VALUES
    ('John Doe', 'john.doe@example.com', 'Engineering', 120000.00, '2024-01-15'),
    ('Jane Smith', 'jane.smith@example.com', 'Engineering', 130000.00, '2024-02-20'),
    ('Mike Johnson', 'mike.johnson@example.com', 'Sales', 95000.00, '2024-03-10'),
    ('Sarah Williams', 'sarah.williams@example.com', 'Marketing', 85000.00, '2023-12-05'),
    ('Tom Brown', 'tom.brown@example.com', 'HR', 75000.00, '2023-11-20'),
    ('Lisa Davis', 'lisa.davis@example.com', 'Finance', 105000.00, '2024-01-25'),
    ('Chris Wilson', 'chris.wilson@example.com', 'Engineering', 115000.00, '2024-02-10'),
    ('Emily Martinez', 'emily.martinez@example.com', 'Sales', 90000.00, '2023-10-15'),
    ('David Anderson', 'david.anderson@example.com', 'Marketing', 80000.00, '2024-03-01'),
    ('Jessica Taylor', 'jessica.taylor@example.com', 'Finance', 110000.00, '2023-09-30');

-- Add indexes for better query performance
CREATE INDEX idx_employees_department ON employees(department);
CREATE INDEX idx_employees_created_at ON employees(created_at);
