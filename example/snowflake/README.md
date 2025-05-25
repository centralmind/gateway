---
title: 'Simple Gateway API Example'
description: 'This example demonstrates a basic setup of the Gateway API with a PostgreSQL database, showcasing how to create a simple REST API service.'
---

This example demonstrates a basic setup of the Gateway API with a PostgreSQL database, showcasing how to create a simple REST API service.

## Components

- **Gateway API**: REST API service with team and persona endpoints
- **PostgreSQL**: Database storing team and persona data

## Prerequisites

- Docker
- Docker Compose

## Getting Started

1. Start all services:
   ```bash
   docker-compose up -d
   ```

2. Services will be available at:
   - Gateway API: http://localhost:8182
   - PostgreSQL: localhost:5432

## API Endpoints

### Teams Endpoints

1. List Teams
```
GET /teams
```
Query parameters:
- `limit` (optional, default: 5): Number of results
- `offset` (optional, default: 0): Pagination offset

2. Get Team by ID
```
GET /teams/{id}
```

3. Get Total Teams Count
```
GET /teams/total_count
```

### Personas Endpoints

1. List Personas
```
GET /personas
```
Query parameters:
- `limit` (optional, default: 5): Number of results
- `offset` (optional, default: 0): Pagination offset

2. Get Persona by ID
```
GET /personas/{id}
```

3. Get Total Personas Count
```
GET /personas/total_count
```

## Database Schema

The database contains two main tables:

### Teams Table
- `id`: Serial Primary Key
- `team_name`: VARCHAR(50)
- `motto`: VARCHAR(100)

### Personas Table
- `id`: Serial Primary Key
- `name`: VARCHAR(50)
- `strength_level`: INT
- `special_move`: VARCHAR(100)
- `favorite_drink`: VARCHAR(50)
- `battle_cry`: VARCHAR(100)
- `team_id`: INT (Foreign Key to Teams Table)

## Configuration Files

- `docker-compose.yml`: Service orchestration
- `config.yaml`: Gateway API configuration with endpoint definitions
- `connection.yaml`: Database connection settings
- `init.sql`: Database initialization script with sample data

## Data Loading

Sample data for teams and personas is automatically loaded during initialization through the `init.sql` script. 
