package postgres

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestPostgresEndpointIntegration tests that all endpoints defined in the configuration work correctly
func TestPostgresEndpointIntegration(t *testing.T) {
	ctx := context.Background()

	// Set up PostgreSQL container
	dbName := "testdb"
	dbUser := "testuser"
	dbPassword := "testpass"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithInitScripts(filepath.Join("testdata", "endpoint_test_data.sql")),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(10*time.Second)),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, testcontainers.TerminateContainer(postgresContainer))
	}()

	// Get connection details
	host, err := postgresContainer.Host(ctx)
	require.NoError(t, err)
	port, err := postgresContainer.MappedPort(ctx, nat.Port("5432/tcp"))
	require.NoError(t, err)

	cfg := Config{
		Hosts:      []string{host},
		Port:       port.Int(),
		Database:   dbName,
		User:       dbUser,
		Password:   dbPassword,
		Schema:     "public",
		IsReadonly: true,
	}

	// Create connector
	conn, err := connectors.New("postgres", cfg)
	require.NoError(t, err)

	// Define test endpoints
	endpoints := []model.Endpoint{
		{
			Group:         "Employees",
			HTTPMethod:    "GET",
			HTTPPath:      "/employees",
			Summary:       "List all employees",
			Query:         "SELECT id, name, email, department, salary FROM employees ORDER BY id LIMIT :limit OFFSET :offset",
			IsArrayResult: true,
			Params: []model.EndpointParams{
				{Name: "limit", Type: "integer", Location: "query", Default: 10},
				{Name: "offset", Type: "integer", Location: "query", Default: 0},
			},
		},
		{
			Group:         "Employees",
			HTTPMethod:    "GET",
			HTTPPath:      "/employees/{id}",
			Summary:       "Get employee by ID",
			Query:         "SELECT id, name, email, department, salary FROM employees WHERE id = :id",
			IsArrayResult: false,
			Params: []model.EndpointParams{
				{Name: "id", Type: "integer", Location: "path", Required: true},
			},
		},
		{
			Group:         "Employees",
			HTTPMethod:    "GET",
			HTTPPath:      "/employees/by_department/{department}",
			Summary:       "Get employees by department",
			Query:         "SELECT id, name, email, department, salary FROM employees WHERE department = :department ORDER BY id",
			IsArrayResult: true,
			Params: []model.EndpointParams{
				{Name: "department", Type: "string", Location: "path", Required: true},
			},
		},
		{
			Group:         "Departments",
			HTTPMethod:    "GET",
			HTTPPath:      "/departments",
			Summary:       "List all departments",
			Query:         "SELECT id, name, budget FROM departments ORDER BY id",
			IsArrayResult: true,
		},
		{
			Group:         "Departments",
			HTTPMethod:    "GET",
			HTTPPath:      "/departments/{id}",
			Summary:       "Get department by ID",
			Query:         "SELECT id, name, budget FROM departments WHERE id = :id",
			IsArrayResult: false,
			Params: []model.EndpointParams{
				{Name: "id", Type: "integer", Location: "path", Required: true},
			},
		},
		{
			Group:         "Statistics",
			HTTPMethod:    "GET",
			HTTPPath:      "/stats/employee_count",
			Summary:       "Get total employee count",
			Query:         "SELECT COUNT(*) as total_count FROM employees",
			IsArrayResult: false,
		},
		{
			Group:      "Statistics",
			HTTPMethod: "GET",
			HTTPPath:   "/stats/department_budget/{id}",
			Summary:    "Get department budget with employee count",
			Query: `SELECT d.name, d.budget, COUNT(e.id) as employee_count 
			           FROM departments d 
			           LEFT JOIN employees e ON d.name = e.department 
			           WHERE d.id = :id 
			           GROUP BY d.id, d.name, d.budget`,
			IsArrayResult: false,
			Params: []model.EndpointParams{
				{Name: "id", Type: "integer", Location: "path", Required: true},
			},
		},
		{
			Group:         "Employees",
			HTTPMethod:    "GET",
			HTTPPath:      "/employee/{id}/salary",
			Summary:       "Get employee salary by ID",
			Query:         "SELECT id, name, salary FROM employees WHERE id = :id",
			IsArrayResult: false,
			Params: []model.EndpointParams{
				{Name: "id", Type: "integer", Location: "path", Required: true},
			},
		},
		{
			Group:         "Departments",
			HTTPMethod:    "GET",
			HTTPPath:      "/departments/{id}/budget",
			Summary:       "Get department budget by ID",
			Query:         "SELECT id, name, budget FROM departments WHERE id = :id",
			IsArrayResult: false,
			Params: []model.EndpointParams{
				{Name: "id", Type: "integer", Location: "path", Required: true},
			},
		},
	}

	// Test each endpoint
	t.Run("ListEmployees", func(t *testing.T) {
		params := map[string]any{"limit": 5, "offset": 0}
		results, err := conn.Query(ctx, endpoints[0], params)
		require.NoError(t, err)
		assert.NotNil(t, results)

		// Should have 5 employees
		assert.Len(t, results, 5)

		// Check first employee structure
		if len(results) > 0 {
			assert.Contains(t, results[0], "id")
			assert.Contains(t, results[0], "name")
			assert.Contains(t, results[0], "email")
			assert.Contains(t, results[0], "department")
		}
	})

	t.Run("GetEmployeeByID", func(t *testing.T) {
		params := map[string]any{"id": 1}
		result, err := conn.Query(ctx, endpoints[1], params)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have exactly one employee
		assert.Len(t, result, 1)
		assert.Equal(t, "John Doe", result[0]["name"])
	})

	t.Run("GetEmployeesByDepartment", func(t *testing.T) {
		params := map[string]any{"department": "Engineering"}
		results, err := conn.Query(ctx, endpoints[2], params)
		require.NoError(t, err)
		assert.NotNil(t, results)

		// Should have 3 engineering employees
		assert.Len(t, results, 3)
		for _, emp := range results {
			assert.Equal(t, "Engineering", emp["department"])
		}
	})

	t.Run("ListDepartments", func(t *testing.T) {
		results, err := conn.Query(ctx, endpoints[3], nil)
		require.NoError(t, err)
		assert.NotNil(t, results)

		// Should have 5 departments
		assert.Len(t, results, 5)

		// Check department structure
		if len(results) > 0 {
			assert.Contains(t, results[0], "id")
			assert.Contains(t, results[0], "name")
			assert.Contains(t, results[0], "budget")
		}
	})

	t.Run("GetDepartmentByID", func(t *testing.T) {
		params := map[string]any{"id": 1}
		result, err := conn.Query(ctx, endpoints[4], params)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have exactly one department
		assert.Len(t, result, 1)
		assert.Equal(t, "Engineering", result[0]["name"])
	})

	t.Run("GetEmployeeCount", func(t *testing.T) {
		result, err := conn.Query(ctx, endpoints[5], nil)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have count result
		assert.Len(t, result, 1)
		assert.Contains(t, result[0], "total_count")
		assert.Equal(t, int64(10), result[0]["total_count"])
	})

	t.Run("GetDepartmentBudgetWithEmployeeCount", func(t *testing.T) {
		params := map[string]any{"id": 1}
		result, err := conn.Query(ctx, endpoints[6], params)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have one result with department info and employee count
		assert.Len(t, result, 1)
		assert.Contains(t, result[0], "name")
		assert.Contains(t, result[0], "budget")
		assert.Contains(t, result[0], "employee_count")
	})

	t.Run("GetEmployeeSalaryByID", func(t *testing.T) {
		params := map[string]any{"id": 1}
		result, err := conn.Query(ctx, endpoints[7], params)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have exactly one employee with salary info
		assert.Len(t, result, 1)
		assert.Contains(t, result[0], "id")
		assert.Contains(t, result[0], "name")
		assert.Contains(t, result[0], "salary")
		assert.Equal(t, "John Doe", result[0]["name"])
	})

	t.Run("GetDepartmentBudgetByID", func(t *testing.T) {
		params := map[string]any{"id": 1}
		result, err := conn.Query(ctx, endpoints[8], params)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have exactly one department with budget info
		assert.Len(t, result, 1)
		assert.Contains(t, result[0], "id")
		assert.Contains(t, result[0], "name")
		assert.Contains(t, result[0], "budget")
		assert.Equal(t, "Engineering", result[0]["name"])
	})
}

// ... rest of the code remains the same ...
